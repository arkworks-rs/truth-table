use crate::{
    id::NodeId,
    verifier::{
        nodes::{VerifierNode, output_logical_plan},
        trees::proof_tree::VerifierProofTree,
    },
};
use arithmetic::{ctx::SharedCtx, table_oracle::TrackedTableOracle, ACTIVATOR_COL_NAME};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
};
use datafusion::{
    arrow::datatypes::Field,
    logical_expr::{self as df, ExprSchemable, LogicalPlan, LogicalPlanBuilder},
    prelude::{Expr, SessionContext},
};
use indexmap::IndexMap;
use ra_toolbox::lp_piop::filter_check::{FilterPIOP, FilterPIOPVerifierInput};
use std::{collections::HashMap, sync::Arc};

use crate::verifier::trees::piop_tree::VerifierPIOPTree;

/// Filter operator that updates the `activator` column based on `predicate`.
///
/// - `predicate`: DataFusion expression applied to rows
/// - `input`: child proof node
/// - `output_plan`: unrolled plan: `input` with this filter’s activator logic
///   applied (pass-through other columns)
pub struct FilterNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub predicate_proof_plan: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub input_proof_plan: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
    pub hint_generation_plans: HashMap<String, LogicalPlan>,
}

impl<F, MvPCS, UvPCS> FilterNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub fn build_output_logical_plan(predicate_expr: Expr, input_plan: LogicalPlan) -> LogicalPlan {
        // Determine activator's datatype from input schema
        let schema = input_plan.schema().clone();
        let activator_field = schema
            .field_with_unqualified_name(ACTIVATOR_COL_NAME)
            .unwrap_or_else(|_| panic!("'activator' column not found in input schema"));
        let activator_dtype = activator_field.data_type().clone();

        // Try boolean AND first; if types mismatch, fall back to 0/1 mask with CASE
        let try_bool_and = df::and(df::col(ACTIVATOR_COL_NAME), predicate_expr.clone());
        let new_activator = if try_bool_and.get_type(schema.as_ref()).is_ok() {
            try_bool_and.alias(ACTIVATOR_COL_NAME)
        } else {
            // Build a 0/1 mask of the same type as activator and bitwise-AND (or use CASE
            // if bitwise not supported)
            let one = df::lit(1)
                .cast_to(&activator_dtype, schema.as_ref())
                .unwrap();
            let zero = df::lit(0)
                .cast_to(&activator_dtype, schema.as_ref())
                .unwrap();
            let mask = df::when(predicate_expr.clone(), one.clone())
                .otherwise(zero.clone())
                .unwrap();

            // Prefer bitwise AND if valid for this dtype, otherwise fallback to CASE
            // replacement
            let try_bit_and = df::bitwise_and(df::col(ACTIVATOR_COL_NAME), mask.clone());
            if try_bit_and.get_type(schema.as_ref()).is_ok() {
                try_bit_and.alias(ACTIVATOR_COL_NAME)
            } else {
                // CASE WHEN predicate THEN activator ELSE 0
                df::when(predicate_expr.clone(), df::col(ACTIVATOR_COL_NAME))
                    .otherwise(zero)
                    .unwrap()
                    .alias(ACTIVATOR_COL_NAME)
            }
        };

        // Pass through all other columns unchanged
        let mut proj_exprs: Vec<df::Expr> = Vec::with_capacity(schema.fields().len());
        for f in schema.fields() {
            if f.name() == ACTIVATOR_COL_NAME {
                proj_exprs.push(new_activator.clone());
            } else {
                proj_exprs.push(df::col(f.name()));
            }
        }

        LogicalPlanBuilder::from(input_plan)
            .project(proj_exprs)
            .unwrap()
            .build()
            .unwrap()
    }
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for FilterNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_lp(
        ctx: &SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        // Match only on filter logical plan
        let filter = match &plan {
            df::LogicalPlan::Filter(f) => f,
            _ => panic!("expected filter logical plan"),
        };

        // The input is itself a logical plan and needs to be proved
        let input_proof_plan =
            VerifierProofTree::<F, MvPCS, UvPCS>::from_lp(ctx, prover_ctx.clone(), &filter.input);
        // Fetching the output logical plan of the input logical plan
        let child_plan = output_logical_plan::<F, MvPCS, UvPCS>(&input_proof_plan.root()).unwrap();
        // Build the output logical plan for this filter node on top of the child output
        // logical plan
        let output_plan = Self::build_output_logical_plan(filter.predicate.clone(), child_plan);
        // The predicate is an expr and needs to be proved
        let predicate_proof_plan = VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
            ctx,
            prover_ctx,
            filter.predicate.clone(),
            &output_plan,
        );
        // Building the witness generation plans map
        Self {
            predicate_proof_plan,
            input_proof_plan: input_proof_plan.root(),
            node_id: NodeId::LP(plan),
            hint_generation_plans: HashMap::new(),
        }
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        vec![&self.input_proof_plan, &self.predicate_proof_plan]
    }
    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(&self) -> HashMap<String, LogicalPlan> {
        self.hint_generation_plans.clone()
    }

    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
    }

    fn name(&self) -> String {
        self.node_id().to_string()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
        verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
        let input_table =
            match piop_tree.tracked_table_oracle(&self.input_proof_plan.node_id(), "output_plan") {
                Some(table) => table,
                None => return,
            };
        let predicate_table = match piop_tree
            .tracked_table_oracle(&self.predicate_proof_plan.node_id(), "output_plan")
        {
            Some(table) => table,
            None => return,
        };
        let tracked_oracles = predicate_table
            .tracked_oracles();
        let (pred_field, pred_poly) = tracked_oracles
            .iter()
            .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
            .or_else(|| tracked_oracles.iter().next())
            .expect("predicate output table must have a column");
        let activator_field = Field::new(ACTIVATOR_COL_NAME, pred_field.data_type().clone(), true);
        let activator_field_ref = datafusion::arrow::datatypes::FieldRef::new(activator_field);
        let mut columns = IndexMap::new();
        for (field, poly) in input_table.tracked_oracles().iter() {
            if field.name() == ACTIVATOR_COL_NAME {
                continue;
            }
            columns.insert(field.clone(), poly.clone());
        }
        columns.insert(activator_field_ref, pred_poly.clone());
        let output_table = TrackedTableOracle::new(None, columns, input_table.log_size());
        piop_tree.add_tracked_table_oracle(
            self.node_id.clone(),
            "output_plan".to_string(),
            output_table,
        );
    }
    fn verify_piop(
        &self,
        verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let filter = match self.node_id().to_lp().unwrap() {
            LogicalPlan::Filter(f) => f.clone(),
            _ => panic!("expected filter logical plan"),
        };

        let predicate_oracle = piop_tree
            .tracked_table_oracle(&NodeId::Expr(filter.predicate.clone()), "output_plan")
            .unwrap()
            .tracked_col_oracle_by_ind(0);
        let input_tracked_Table_oracle = piop_tree
            .tracked_table_oracle(&NodeId::LP(filter.input.as_ref().clone()), "output_plan")
            .unwrap()
            .clone();
        let output_tracked_Table_oracle = piop_tree
            .tracked_table_oracle(&self.input_proof_plan.node_id(), "output_plan")
            .unwrap()
            .clone();

        let filter_piop_verifier_input = FilterPIOPVerifierInput {
            filter,
            predicate_oracle,
            input_tracked_Table_oracle,
            output_tracked_Table_oracle,
        };

        FilterPIOP::<F, MvPCS, UvPCS>::verify(verifier, filter_piop_verifier_input)
    }
}

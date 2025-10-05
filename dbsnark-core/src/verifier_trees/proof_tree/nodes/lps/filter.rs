use crate::{
    id::NodeId,
    verifier_trees::proof_tree::{
        VerifierProofTree,
        nodes::{VerifierNode, output_logical_plan},
    },
};
use arithmetic::ctx::SharedCtx;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::Prover,
};
use datafusion::{
    logical_expr::{self as df, ExprSchemable, LogicalPlan, LogicalPlanBuilder},
    prelude::{Expr, SessionContext},
};
use ra_toolbox::lp_piop::filter_check::{FilterPIOP, FilterPIOPProverInput};
use std::{collections::HashMap, sync::Arc};

use crate::verifier_trees::piop_tree::VerifierPIOPTree;

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
            .field_with_unqualified_name("activator")
            .unwrap_or_else(|_| panic!("'activator' column not found in input schema"));
        let activator_dtype = activator_field.data_type().clone();

        // Try boolean AND first; if types mismatch, fall back to 0/1 mask with CASE
        let try_bool_and = df::and(df::col("activator"), predicate_expr.clone());
        let new_activator = if try_bool_and.get_type(schema.as_ref()).is_ok() {
            try_bool_and.alias("activator")
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
            let try_bit_and = df::bitwise_and(df::col("activator"), mask.clone());
            if try_bit_and.get_type(schema.as_ref()).is_ok() {
                try_bit_and.alias("activator")
            } else {
                // CASE WHEN predicate THEN activator ELSE 0
                df::when(predicate_expr.clone(), df::col("activator"))
                    .otherwise(zero)
                    .unwrap()
                    .alias("activator")
            }
        };

        // Pass through all other columns unchanged
        let mut proj_exprs: Vec<df::Expr> = Vec::with_capacity(schema.fields().len());
        for f in schema.fields() {
            if f.name() == "activator" {
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
        // Build the
        // output logical plan for this filter node on top of the child output
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
        let hint_generation_plans =
            HashMap::from([("output_plan".to_string(), output_plan.clone())]);
        Self {
            predicate_proof_plan,
            input_proof_plan: input_proof_plan.root(),
            node_id: NodeId::LP(plan),
            hint_generation_plans,
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
        prover: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
    }
    fn verify_piop(
        &self,
        prover: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        todo!()
        // let filter = match self.node_id().to_lp().unwrap() {
        //     LogicalPlan::Filter(f) => f.clone(),
        //     _ => panic!("expected filter logical plan"),
        // };

        // let predicate_col = piop_tree
        //     .table(&NodeId::Expr(filter.predicate.clone()), "output_plan")
        //     .unwrap()
        //     .col(0);
        // let input_tracked_Table = piop_tree
        //     .table(&NodeId::LP(filter.input.as_ref().clone()), "output_plan")
        //     .unwrap()
        //     .clone();
        // let output_tracked_Table = piop_tree
        //     .table(&self.input_proof_plan.node_id(), "output_plan")
        //     .unwrap()
        //     .clone();

        // let filter_piop_verifier_input = FilterPIOPProverInput {
        //     filter,
        //     predicate_col,
        //     input_tracked_Table,
        //     output_tracked_Table,
        // };

        // FilterPIOP::<F, MvPCS, UvPCS>::prove(prover,
        // filter_piop_verifier_input)
    }
}

use datafusion::{
    logical_expr::{self as df, ExprSchemable, LogicalPlan, LogicalPlanBuilder},
    prelude::{Expr, SessionContext},
};
use std::{collections::HashMap, sync::Arc};

use crate::{
    nodes::{ProverNode, ProverNodeNodeId, expr_to_proof_plan, output_logical_plan},
    trees::proof_tree::ProofTree,
};

/// Filter operator that updates the `activator` column based on `predicate`.
///
/// - `predicate`: DataFusion expression applied to rows
/// - `input`: child proof node
/// - `output_plan`: unrolled plan: `input` with this filter’s activator logic
///   applied (pass-through other columns)
pub struct FilterNode {
    pub predicate_proof_plan: Arc<dyn ProverNode>,
    pub input_proof_plan: Arc<dyn ProverNode>,
    pub node_id: ProverNodeNodeId,
    pub proof_trees: HashMap<String, LogicalPlan>,
}

impl FilterNode {
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

impl ProverNode for FilterNode {
    fn from_logical_plan(ctx: &SessionContext, plan: LogicalPlan) -> Self
    where
        Self: Sized,
    {
        // Match only on filter logical plan
        let filter = match &plan {
            df::LogicalPlan::Filter(f) => f,
            _ => panic!("expected filter logical plan"),
        };

        // The input is itself a logical plan and needs to be proved
        let input_proof_plan = ProofTree::from_logical_plan(ctx, &filter.input);
        // Fetching the output logical plan of the input logical plan
        let child_plan = output_logical_plan(&input_proof_plan.root()).unwrap();
        // Build the output logical plan for this filter node on top of the child output
        // logical plan
        let output_plan = Self::build_output_logical_plan(filter.predicate.clone(), child_plan);
        // The predicate is an expr and needs to be proved
        let predicate_proof_plan = expr_to_proof_plan(ctx, filter.predicate.clone(), &output_plan);
        // Building the witness generation plans map
        let proof_trees = HashMap::from([("output_plan".to_string(), output_plan.clone())]);
        Self {
            predicate_proof_plan,
            input_proof_plan: input_proof_plan.root(),
            node_id: ProverNodeNodeId::LP(plan),
            proof_trees,
        }
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode>> {
        vec![&self.input_proof_plan, &self.predicate_proof_plan]
    }
    fn node_id(&self) -> ProverNodeNodeId {
        self.node_id.clone()
    }

    fn proof_trees(&self) -> HashMap<String, LogicalPlan> {
        self.proof_trees.clone()
    }

    fn piop_plan(&self) {
        todo!()
    }
}

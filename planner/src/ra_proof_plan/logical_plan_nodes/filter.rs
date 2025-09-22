use crate::ra_proof_plan::{
    expr_to_proof_plan, primary_witness_plan, relative_plan_opt, ProofPlan, ProofPlanNodeType,
};
use datafusion::{
    logical_expr::{self as df, ExprSchemable, LogicalPlan, LogicalPlanBuilder},
    prelude::SessionContext,
};
use std::{collections::HashMap, sync::Arc};

/// Filter operator that updates the `activator` column based on `predicate`.
///
/// - `predicate`: DataFusion expression applied to rows
/// - `input`: child proof node
/// - `absolute_plan`: unrolled plan: `input` with this filter’s activator logic
///   applied (pass-through other columns)
pub struct FilterNode {
    pub predicate: Arc<dyn ProofPlan>,
    pub input: Arc<dyn ProofPlan>,
    pub node_type: ProofPlanNodeType,
    pub witness_generation_plans: HashMap<String, LogicalPlan>,
}

impl FilterNode {
    pub fn make_relative_plan(
        predicate: &Arc<dyn ProofPlan>,
        input_plan: LogicalPlan,
    ) -> LogicalPlan {
        // Build relative plan by propagating input and zeroing `activator` when
        // predicate is false.
        let predicate_expr = match predicate.node_type() {
            ProofPlanNodeType::Expr(expr) => expr,
            _ => panic!("expected expression proof plan"),
        };

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

    pub fn new(
        ctx: &SessionContext,
        predicate: df::Expr,
        input_plan: LogicalPlan,
        input: Arc<dyn ProofPlan>,
    ) -> Self {
        let predicate_node = expr_to_proof_plan(predicate, &input_plan);
        let child_plan = primary_witness_plan(&input)
            .or_else(|| relative_plan_opt(&input))
            .expect("filter child witness plan unavailable");
        let relative_plan = Self::make_relative_plan(&predicate_node, child_plan);
        let mut witness_generation_plans = HashMap::new();
        witness_generation_plans.insert("absolute_output".to_string(), relative_plan.clone());
        Self {
            predicate: predicate_node,
            input,
            node_type: ProofPlanNodeType::LogicalPlan(input_plan),
            witness_generation_plans,
        }
    }
}

impl ProofPlan for FilterNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        vec![&self.input, &self.predicate]
    }
    fn node_type(&self) -> ProofPlanNodeType {
        self.node_type.clone()
    }

    fn witness_generation_plans(&self) -> HashMap<String, LogicalPlan> {
        self.witness_generation_plans.clone()
    }
}

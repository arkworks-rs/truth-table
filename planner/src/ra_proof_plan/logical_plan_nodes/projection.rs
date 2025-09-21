use crate::ra_proof_plan::{ProofPlan, ProofPlanNodeType};
use datafusion::{
    logical_expr::{LogicalPlan, LogicalPlanBuilder},
    prelude::{col, Expr, SessionContext},
};
use std::{collections::HashMap, sync::Arc};

/// Projection operator that preserves the `activator` column.
///
/// - `expr`: projection expressions from the original logical plan
/// - `input`: child proof node
/// - witness plans include the optimized projection ("absolute_output") and the
///   relative projection plan ("relative_output").
pub struct ProjectionNode {
    pub expr: Vec<Arc<dyn ProofPlan>>,
    pub input: Arc<dyn ProofPlan>,
    pub node_type: ProofPlanNodeType,
    pub witness_generation_plans: HashMap<String, LogicalPlan>,
}

impl ProjectionNode {
    pub fn make_relative_plan(
        expr: Vec<Arc<dyn ProofPlan>>,
        input_plan: LogicalPlan,
    ) -> LogicalPlan {
        let schema = input_plan.schema();

        // Preserve `activator` if present, but avoid duplicates (explicit, alias, or
        // wildcard)
        let mut exprs: Vec<Expr> = expr
            .iter()
            .map(|e| match e.node_type() {
                ProofPlanNodeType::Expr(expr) => expr,
                _ => panic!("expected expression proof plan"),
            })
            .collect();
        if schema.field_with_unqualified_name("activator").is_ok() {
            let projects_activator = exprs.iter().any(|e| match e {
                Expr::Column(c) => c.name == "activator",
                Expr::Alias(a) => a.name == "activator",
                Expr::Wildcard { .. } => true,
                _ => false,
            });
            if !projects_activator {
                exprs.push(col("activator"));
            }
        }

        LogicalPlanBuilder::from(input_plan)
            .project(exprs)
            .unwrap()
            .build()
            .unwrap()
    }

    pub fn new(
        ctx: &SessionContext,
        expr: Vec<Arc<dyn ProofPlan>>,
        input_plan: LogicalPlan,
        input: Arc<dyn ProofPlan>,
    ) -> Self {
        let relative_plan = Self::make_relative_plan(expr.clone(), input_plan.clone());
        let absolute_plan = ctx.state().optimize(&relative_plan).unwrap();
        let mut witness_generation_plans = HashMap::new();
        witness_generation_plans.insert("absolute_output".to_string(), absolute_plan);
        witness_generation_plans.insert("relative_output".to_string(), relative_plan.clone());
        ProjectionNode {
            expr,
            input,
            node_type: ProofPlanNodeType::LogicalPlan(relative_plan),
            witness_generation_plans,
        }
    }
}
impl ProofPlan for ProjectionNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        vec![&self.input]
    }

    fn node_type(&self) -> ProofPlanNodeType {
        self.node_type.clone()
    }

    fn witness_generation_plans(&self) -> HashMap<String, LogicalPlan> {
        self.witness_generation_plans.clone()
    }
}

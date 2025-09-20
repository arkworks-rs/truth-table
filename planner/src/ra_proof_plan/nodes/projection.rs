use crate::ra_proof_plan::RAProofPlan;
use datafusion::{
    logical_expr::{LogicalPlan, LogicalPlanBuilder},
    prelude::{col, Expr, SessionContext},
};
use std::sync::Arc;

/// Projection operator that preserves the `activator` column.
///
/// - `expr`: projection expressions from the original logical plan
/// - `input`: child proof node
/// - `absolute_plan`: unrolled plan: `input.absolute_plan` with this projection
///   applied (and `activator` preserved if present)
pub struct ProjectionNode {
    pub expr: Vec<Expr>,
    pub input: Arc<dyn RAProofPlan>,
    pub relative_plan: LogicalPlan,
    pub absolute_plan: LogicalPlan,
}
impl ProjectionNode {
    pub fn make_relative_plan(expr: Vec<Expr>, input: Arc<dyn RAProofPlan>) -> LogicalPlan {
        let input_plan = input.relative_plan();
        let schema = input_plan.schema();

        // Preserve `activator` if present, but avoid duplicates (explicit, alias, or
        // wildcard)
        let mut exprs = expr.clone();
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
    pub fn new(ctx: &SessionContext, expr: Vec<Expr>, input: Arc<dyn RAProofPlan>) -> Self {
        let relative_plan = Self::make_relative_plan(expr.clone(), input.clone());
        let absolute_plan = ctx.state().optimize(&relative_plan).unwrap();
        ProjectionNode {
            expr,
            input,
            relative_plan,
            absolute_plan,
        }
    }
}
impl RAProofPlan for ProjectionNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "ProjectionNode"
    }

    fn children(&self) -> Vec<&Arc<dyn RAProofPlan>> {
        vec![&self.input]
    }

    fn relative_plan(&self) -> LogicalPlan {
        self.relative_plan.clone()
    }

    fn absolute_plan(&self) -> LogicalPlan {
        self.absolute_plan.clone()
    }
}

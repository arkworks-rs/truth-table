use std::sync::Arc;

use datafusion::logical_expr::Expr;

use crate::nodes::{ProofPlan, ProofPlanNodeId};
#[derive(Clone)]
pub struct BetweenExprNode {
    pub relative_expr: Expr,
    pub output_expr: Expr,
    pub inputs: Vec<Arc<dyn ProofPlan>>,
}

impl ProofPlan for BetweenExprNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn node_id(&self) -> ProofPlanNodeId {
        ProofPlanNodeId::Expr(self.relative_expr.clone())
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        self.inputs.iter().collect()
    }

    fn from_expr(
        ctx: &datafusion::prelude::SessionContext,
        expr: Expr,
        parent_logical_plan: datafusion::logical_expr::LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        todo!()
    }

    fn piop_plan(&self) {
        todo!()
    }
}

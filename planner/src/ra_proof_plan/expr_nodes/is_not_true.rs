use std::sync::Arc;

use datafusion::logical_expr::Expr;

use crate::ra_proof_plan::{ProofPlan, ProofPlanNodeId};

#[derive(Clone)]
pub struct IsNotTrueExprNode {
    pub relative_expr: Expr,
    pub output_expr: Expr,
    pub inputs: Vec<Arc<dyn ProofPlan>>,
}

impl ProofPlan for IsNotTrueExprNode {
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
}

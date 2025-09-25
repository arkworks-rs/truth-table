use std::sync::Arc;

use datafusion::{logical_expr::Expr, scalar::ScalarValue};

use crate::ra_proof_plan::{ProofPlan, ProofPlanNodeId};

#[derive(Clone)]
pub struct LiteralExprNode {
    pub node_id: ProofPlanNodeId,
}

impl ProofPlan for LiteralExprNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn node_id(&self) -> ProofPlanNodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        Vec::new()
    }

    fn from_expr(
        ctx: &datafusion::prelude::SessionContext,
        expr: Expr,
        parent_logical_plan: datafusion::logical_expr::LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        Self {
            node_id: ProofPlanNodeId::Expr(expr),
        }
    }
}

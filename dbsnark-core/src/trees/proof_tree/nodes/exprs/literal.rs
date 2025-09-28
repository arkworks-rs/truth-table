use std::sync::Arc;

use datafusion::{logical_expr::Expr, scalar::ScalarValue};

use crate::trees::proof_tree::nodes::{ProverNode, ProverNodeNodeId};

#[derive(Clone)]
pub struct LiteralExprNode {
    pub node_id: ProverNodeNodeId,
}

impl ProverNode for LiteralExprNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn node_id(&self) -> ProverNodeNodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode>> {
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
            node_id: ProverNodeNodeId::Expr(expr),
        }
    }

    fn piop_plan(&self) {
        todo!()
    }
}

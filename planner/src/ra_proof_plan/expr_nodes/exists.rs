use std::sync::Arc;

use datafusion::logical_expr::Expr;

use crate::ra_proof_plan::{ProofPlan, ProofPlanNodeType};

#[derive(Clone)]
pub struct ExistsExprNode {
    pub inputs: Vec<Arc<dyn ProofPlan>>,
    pub node_type: ProofPlanNodeType,
}

impl ProofPlan for ExistsExprNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn node_type(&self) -> ProofPlanNodeType {
        self.node_type.clone()
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

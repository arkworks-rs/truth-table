use std::sync::Arc;

use datafusion::{logical_expr::Expr, scalar::ScalarValue};

use crate::ra_proof_plan::{ProofPlan, ProofPlanNodeType};

#[derive(Clone)]
pub struct LiteralExprNode {
    pub node_type: ProofPlanNodeType,
}

impl LiteralExprNode {
    pub fn new(scalar_value: ScalarValue) -> Self {
        Self {
            node_type: ProofPlanNodeType::Expr(Expr::Literal(scalar_value)),
        }
    }
}

impl ProofPlan for LiteralExprNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn node_type(&self) -> ProofPlanNodeType {
        self.node_type.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        Vec::new()
    }
}

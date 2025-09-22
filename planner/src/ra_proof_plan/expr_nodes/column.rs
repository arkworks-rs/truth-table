use std::sync::Arc;

use datafusion::{logical_expr::Expr, prelude::Column};

use crate::ra_proof_plan::{column, ProofPlan, ProofPlanNodeType};

#[derive(Clone)]
pub struct ColumnExprNode {
    pub node_type: ProofPlanNodeType,
}

impl ColumnExprNode {
    pub fn new(column: Column) -> Self {
        Self {
            node_type: ProofPlanNodeType::Expr(Expr::Column(column)),
        }
    }
}

impl ProofPlan for ColumnExprNode {
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

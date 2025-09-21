use std::sync::Arc;

use datafusion::logical_expr::Expr;

use crate::ra_proof_plan::{ProofPlan, ProofPlanNodeType};

#[derive(Clone)]
pub struct ScalarSubqueryExprNode {
    pub relative_expr: Expr,
    pub absolute_expr: Expr,
    pub inputs: Vec<Arc<dyn ProofPlan>>,
}

impl ScalarSubqueryExprNode {
    pub fn new(relative_expr: Expr, absolute_expr: Expr, inputs: Vec<Arc<dyn ProofPlan>>) -> Self {
        Self {
            relative_expr,
            absolute_expr,
            inputs,
        }
    }
}

impl ProofPlan for ScalarSubqueryExprNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn node_type(&self) -> ProofPlanNodeType {
        ProofPlanNodeType::Expr(self.relative_expr.clone())
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        self.inputs.iter().collect()
    }
}

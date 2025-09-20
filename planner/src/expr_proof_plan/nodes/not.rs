use std::sync::Arc;

use datafusion::sql::sqlparser::ast::Expr;

use crate::expr_proof_plan::ExprProofPlan;

#[derive(Clone)]
pub struct NotExprNode {
    pub relative_expr: Expr,
    pub absolute_expr: Expr,
    pub inputs: Vec<Arc<dyn ExprProofPlan>>,
}

impl NotExprNode {
    pub fn new(
        relative_expr: Expr,
        absolute_expr: Expr,
        inputs: Vec<Arc<dyn ExprProofPlan>>,
    ) -> Self {
        Self {
            relative_expr,
            absolute_expr,
            inputs,
        }
    }
}

impl ExprProofPlan for NotExprNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "NotExprNode"
    }

    fn rel_expr(&self) -> Expr {
        self.relative_expr.clone()
    }

    fn absolute_expr(&self) -> Expr {
        self.absolute_expr.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn ExprProofPlan>> {
        self.inputs.iter().collect()
    }
}

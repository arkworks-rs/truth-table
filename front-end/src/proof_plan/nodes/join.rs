use super::ProofNode;
use crate::proof_plan::ProofPlan;
use datafusion::logical_expr as df;

#[derive(Debug, Clone)]
pub struct JoinNode {
    pub left: Box<ProofPlan>,
    pub right: Box<ProofPlan>,
    pub on: Vec<(df::Expr, df::Expr)>,
    pub filter: Option<df::Expr>,
    pub join_type: df::JoinType,
    pub null_equals_null: bool,
}

impl ProofNode for JoinNode {
    type LogicalCounterpart = df::Join;
    fn from_logical(lp: &Self::LogicalCounterpart) -> Self {
        Self {
            left: Box::new(ProofPlan::from_logical_plan(&lp.left)),
            right: Box::new(ProofPlan::from_logical_plan(&lp.right)),
            on: lp.on.clone(),
            filter: lp.filter.clone(),
            join_type: lp.join_type,
            null_equals_null: lp.null_equals_null,
        }
    }
    fn io_plan(lp: &Self::LogicalCounterpart) -> df::LogicalPlan {
        df::LogicalPlan::Join(lp.clone())
    }
}

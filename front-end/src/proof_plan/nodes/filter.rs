use super::ProofNode;
use crate::proof_plan::ProofPlan;
use datafusion::logical_expr as df;

#[derive(Debug, Clone)]
pub struct FilterNode {
    pub predicate: df::Expr,
    pub input: Box<ProofPlan>,
}

impl ProofNode for FilterNode {
    type LogicalCounterpart = df::Filter;
    fn from_logical(lp: &Self::LogicalCounterpart) -> Self {
        Self {
            predicate: lp.predicate.clone(),
            input: Box::new(ProofPlan::from_logical_plan(&lp.input)),
        }
    }
    fn io_plan(lp: &Self::LogicalCounterpart) -> df::LogicalPlan {
        df::LogicalPlan::Filter(lp.clone())
    }
}

use super::ProofNode;
use crate::proof_plan::ProofPlan;
use datafusion::logical_expr as df;

#[derive(Debug, Clone)]
pub struct LimitNode {
    pub skip: Option<df::Expr>,
    pub fetch: Option<df::Expr>,
    pub input: Box<ProofPlan>,
}

impl ProofNode for LimitNode {
    type LogicalCounterpart = df::Limit;
    fn from_logical(lp: &Self::LogicalCounterpart) -> Self {
        Self {
            skip: lp.skip.as_deref().cloned(),
            fetch: lp.fetch.as_deref().cloned(),
            input: Box::new(ProofPlan::from_logical_plan(&lp.input)),
        }
    }
    fn io_plan(lp: &Self::LogicalCounterpart) -> df::LogicalPlan {
        df::LogicalPlan::Limit(lp.clone())
    }
}

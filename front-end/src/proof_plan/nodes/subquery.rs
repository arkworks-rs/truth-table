use super::ProofNode;
use crate::proof_plan::ProofPlan;
use datafusion::logical_expr as df;

#[derive(Debug, Clone)]
pub struct SubqueryNode {
    pub input: Box<ProofPlan>,
}

impl ProofNode for SubqueryNode {
    type LogicalCounterpart = df::Subquery;
    fn from_logical(lp: &Self::LogicalCounterpart) -> Self {
        Self {
            input: Box::new(ProofPlan::from_logical_plan(&lp.subquery)),
        }
    }
    fn io_plan(lp: &Self::LogicalCounterpart) -> df::LogicalPlan {
        df::LogicalPlan::Subquery(lp.clone())
    }
}

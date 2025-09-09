use super::ProofNode;
use crate::proof_plan::ProofPlan;
use datafusion::logical_expr as df;

#[derive(Debug, Clone)]
pub struct DistinctNode {
    pub input: Box<ProofPlan>,
}

impl ProofNode for DistinctNode {
    type LogicalCounterpart = df::Distinct;
    fn from_logical(lp: &Self::LogicalCounterpart) -> Self {
        Self {
            input: Box::new(ProofPlan::from_logical_plan(lp.input())),
        }
    }
    fn io_plan(lp: &Self::LogicalCounterpart) -> df::LogicalPlan {
        df::LogicalPlan::Distinct(lp.clone())
    }
}

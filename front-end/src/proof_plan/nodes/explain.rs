use super::ProofNode;
use crate::proof_plan::ProofPlan;
use datafusion::logical_expr as df;

#[derive(Debug, Clone)]
pub struct ExplainNode {
    pub input: Box<ProofPlan>,
}

impl ProofNode for ExplainNode {
    type LogicalCounterpart = df::Explain;
    fn from_logical(lp: &Self::LogicalCounterpart) -> Self {
        Self {
            input: Box::new(ProofPlan::from_logical_plan(&lp.plan)),
        }
    }
    fn io_plan(lp: &Self::LogicalCounterpart) -> df::LogicalPlan {
        df::LogicalPlan::Explain(lp.clone())
    }
}

use super::ProofNode;
use crate::proof_plan::ProofPlan;
use datafusion::logical_expr as df;

#[derive(Debug, Clone)]
pub struct OtherNode {
    pub inputs: Vec<ProofPlan>,
    pub kind: String,
}

impl ProofNode for OtherNode {
    type LogicalCounterpart = df::LogicalPlan;
    fn from_logical(lp: &Self::LogicalCounterpart) -> Self {
        Self {
            inputs: lp
                .inputs()
                .iter()
                .map(|i| ProofPlan::from_logical_plan(i))
                .collect(),
            kind: format!("{}", lp.display()),
        }
    }
    fn io_plan(lp: &Self::LogicalCounterpart) -> df::LogicalPlan {
        lp.clone()
    }
}

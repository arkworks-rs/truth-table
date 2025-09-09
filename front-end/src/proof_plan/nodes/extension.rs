use super::ProofNode;
use crate::proof_plan::ProofPlan;
use datafusion::logical_expr as df;

#[derive(Debug, Clone)]
pub struct ExtensionNode {
    pub inputs: Vec<ProofPlan>,
}

impl ProofNode for ExtensionNode {
    type LogicalCounterpart = df::Extension;
    fn from_logical(lp: &Self::LogicalCounterpart) -> Self {
        Self {
            inputs: lp
                .node
                .inputs()
                .iter()
                .map(|i| ProofPlan::from_logical_plan(i))
                .collect(),
        }
    }
    fn io_plan(lp: &Self::LogicalCounterpart) -> df::LogicalPlan {
        df::LogicalPlan::Extension(lp.clone())
    }
}

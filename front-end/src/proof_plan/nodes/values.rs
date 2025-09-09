use super::ProofNode;
use datafusion::logical_expr as df;

#[derive(Debug, Clone)]
pub struct ValuesNode;

impl ProofNode for ValuesNode {
    type LogicalCounterpart = df::Values;
    fn from_logical(lp: &Self::LogicalCounterpart) -> Self {
        ValuesNode
    }
    fn io_plan(lp: &Self::LogicalCounterpart) -> df::LogicalPlan {
        df::LogicalPlan::Values(lp.clone())
    }
}

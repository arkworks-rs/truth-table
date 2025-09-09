use super::ProofNode;
use crate::proof_plan::ProofPlan;
use datafusion::logical_expr as df;

#[derive(Debug, Clone)]
pub struct SubqueryAliasNode {
    pub alias: String,
    pub input: Box<ProofPlan>,
}

impl ProofNode for SubqueryAliasNode {
    type LogicalCounterpart = df::SubqueryAlias;
    fn from_logical(lp: &Self::LogicalCounterpart) -> Self {
        Self {
            alias: lp.alias.to_string(),
            input: Box::new(ProofPlan::from_logical_plan(&lp.input)),
        }
    }
    fn io_plan(lp: &Self::LogicalCounterpart) -> df::LogicalPlan {
        df::LogicalPlan::SubqueryAlias(lp.clone())
    }
}

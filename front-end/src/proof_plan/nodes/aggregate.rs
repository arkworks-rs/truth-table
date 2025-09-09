use super::ProofNode;
use crate::proof_plan::ProofPlan;
use datafusion::logical_expr as df;

#[derive(Debug, Clone)]
pub struct AggregateNode {
    pub group_expr: Vec<df::Expr>,
    pub aggr_expr: Vec<df::Expr>,
    pub input: Box<ProofPlan>,
}

impl ProofNode for AggregateNode {
    type LogicalCounterpart = df::Aggregate;
    fn from_logical(lp: &Self::LogicalCounterpart) -> Self {
        Self {
            group_expr: lp.group_expr.clone(),
            aggr_expr: lp.aggr_expr.clone(),
            input: Box::new(ProofPlan::from_logical_plan(&lp.input)),
        }
    }
    fn io_plan(lp: &Self::LogicalCounterpart) -> df::LogicalPlan {
        df::LogicalPlan::Aggregate(lp.clone())
    }
}

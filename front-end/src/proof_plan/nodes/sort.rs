use super::ProofNode;
use crate::proof_plan::ProofPlan;
use datafusion::logical_expr as df;

#[derive(Debug, Clone)]
pub struct SortNode {
    pub sort_expr: Vec<(df::Expr, bool, bool)>,
    pub fetch: Option<usize>,
    pub input: Box<ProofPlan>,
}

impl ProofNode for SortNode {
    type LogicalCounterpart = df::Sort;
    fn from_logical(lp: &Self::LogicalCounterpart) -> Self {
        let sort_expr = lp
            .expr
            .iter()
            .map(|se| (se.expr.clone(), se.asc, se.nulls_first))
            .collect();
        Self {
            sort_expr,
            fetch: lp.fetch,
            input: Box::new(ProofPlan::from_logical_plan(&lp.input)),
        }
    }
    fn io_plan(lp: &Self::LogicalCounterpart) -> df::LogicalPlan {
        df::LogicalPlan::Sort(lp.clone())
    }
}

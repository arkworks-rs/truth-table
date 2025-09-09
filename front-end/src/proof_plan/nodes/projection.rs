use super::{mask_first_col, ProofNode};
use crate::proof_plan::ProofPlan;
use datafusion::logical_expr as df;

#[derive(Debug, Clone)]
pub struct ProjectionNode {
    pub expr: Vec<df::Expr>,
    pub input: Box<ProofPlan>,
}

impl ProofNode for ProjectionNode {
    type LogicalCounterpart = df::Projection;
    fn from_logical(lp: &Self::LogicalCounterpart) -> Self {
        Self {
            expr: lp.expr.clone(),
            input: Box::new(ProofPlan::from_logical_plan(&lp.input)),
        }
    }
    fn io_plan(lp: &Self::LogicalCounterpart) -> df::LogicalPlan {
        match lp.input.as_ref() {
            df::LogicalPlan::Filter(f) => mask_first_col(&f.input, &f.predicate),
            _ => df::LogicalPlan::Projection(lp.clone()),
        }
    }
}

use super::ProofNode;
use crate::proof_plan::ProofPlan;
use datafusion::logical_expr as df;

#[derive(Debug, Clone)]
pub struct WindowNode {
    pub window_expr: Vec<df::Expr>,
    pub input: Box<ProofPlan>,
}

impl ProofNode for WindowNode {
    type LogicalCounterpart = df::Window;
    fn from_logical(lp: &Self::LogicalCounterpart) -> Self {
        Self {
            window_expr: lp.window_expr.clone(),
            input: Box::new(ProofPlan::from_logical_plan(&lp.input)),
        }
    }
    fn io_plan(lp: &Self::LogicalCounterpart) -> df::LogicalPlan {
        df::LogicalPlan::Window(lp.clone())
    }
}

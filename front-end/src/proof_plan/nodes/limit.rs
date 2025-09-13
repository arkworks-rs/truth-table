use crate::proof_plan::ProofPlan;
use datafusion::{catalog::Session, logical_expr as df, prelude::SessionContext};
use std::sync::Arc;

pub struct LimitNode {
    pub skip: Option<df::Expr>,
    pub fetch: Option<df::Expr>,
    pub input: Arc<dyn ProofPlan>,
}

impl LimitNode {
    pub fn new(
        ctx: &SessionContext,
        skip: Option<df::Expr>,
        fetch: Option<df::Expr>,
        input: Arc<dyn ProofPlan>,
    ) -> Self {
        todo!()
    }
}

impl ProofPlan for LimitNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "LimitNode"
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        Vec::new()
    }

    fn relative_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }

    fn absolute_plan(&self) -> df::LogicalPlan {
        todo!()
    }
}

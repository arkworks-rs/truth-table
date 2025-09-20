use std::sync::Arc;

use crate::ra_proof_plan::RAProofPlan;
use datafusion::{logical_expr as df, prelude::SessionContext};

pub struct WindowNode {
    pub window_expr: Vec<df::Expr>,
    pub input: Arc<dyn RAProofPlan>,
}

impl WindowNode {
    pub fn new(
        ctx: &SessionContext,
        window_expr: Vec<df::Expr>,
        input: Arc<dyn RAProofPlan>,
    ) -> Self {
        todo!()
    }
}

impl RAProofPlan for WindowNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "WindowNode"
    }

    fn children(&self) -> Vec<&Arc<dyn RAProofPlan>> {
        vec![&self.input]
    }

    fn relative_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }

    fn absolute_plan(&self) -> df::LogicalPlan {
        todo!()
    }
}

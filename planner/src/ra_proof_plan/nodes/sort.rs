use std::sync::Arc;

use crate::ra_proof_plan::RAProofPlan;
use datafusion::{logical_expr as df, prelude::SessionContext};

pub struct SortNode {
    pub sort_expr: Vec<(df::Expr, bool, bool)>,
    pub fetch: Option<usize>,
    pub input: Arc<dyn RAProofPlan>,
}

impl SortNode {
    pub fn new(
        ctx: SessionContext,
        sort_expr: Vec<(df::Expr, bool, bool)>,
        fetch: Option<usize>,
        input: Arc<dyn RAProofPlan>,
    ) -> Self {
        todo!()
    }
}

impl RAProofPlan for SortNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "SortNode"
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

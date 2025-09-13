use std::sync::Arc;

use crate::proof_plan::ProofPlan;
use datafusion::{logical_expr as df, prelude::SessionContext};

pub struct SortNode {
    pub sort_expr: Vec<(df::Expr, bool, bool)>,
    pub fetch: Option<usize>,
    pub input: Arc<dyn ProofPlan>,
}

impl SortNode {
    pub fn new(
        ctx: SessionContext,
        sort_expr: Vec<(df::Expr, bool, bool)>,
        fetch: Option<usize>,
        input: Arc<dyn ProofPlan>,
    ) -> Self {
        todo!()
    }
}

impl ProofPlan for SortNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "SortNode"
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        vec![&self.input]
    }

    fn relative_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }

    fn absolute_plan(&self) -> df::LogicalPlan {
        todo!()
    }
}

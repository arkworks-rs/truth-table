use std::sync::Arc;

use datafusion::{logical_expr::LogicalPlan, prelude::SessionContext};

use crate::proof_plan::ProofPlan;

pub struct AnalyzeNode {
    pub input: Arc<dyn ProofPlan>,
}

impl AnalyzeNode {
    pub fn new(ctx: &mut SessionContext, input: Arc<dyn ProofPlan>) -> Self {
        todo!()
    }
}

impl ProofPlan for AnalyzeNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "AnalyzeNode"
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        vec![&self.input]
    }

    fn relative_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }

    fn absolute_plan(&self) -> LogicalPlan {
        todo!()
    }
}

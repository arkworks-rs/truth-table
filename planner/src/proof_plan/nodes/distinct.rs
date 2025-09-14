use std::sync::Arc;

use datafusion::{logical_expr::LogicalPlan, prelude::SessionContext};

use crate::proof_plan::ProofPlan;

pub struct DistinctNode {
    pub input: Arc<dyn ProofPlan>,
}
impl DistinctNode {
    pub fn new(ctx: &mut SessionContext, input: Arc<dyn ProofPlan>) -> Self {
        todo!()
    }
}
impl ProofPlan for DistinctNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "DistinctNode"
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        vec![&self.input]
    }

    fn relative_plan(&self) -> LogicalPlan {
        todo!()
    }

    fn absolute_plan(&self) -> LogicalPlan {
        todo!()
    }
}

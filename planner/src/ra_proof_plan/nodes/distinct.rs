use std::sync::Arc;

use datafusion::{logical_expr::LogicalPlan, prelude::SessionContext};

use crate::ra_proof_plan::RAProofPlan;

pub struct DistinctNode {
    pub input: Arc<dyn RAProofPlan>,
}
impl DistinctNode {
    pub fn new(ctx: &mut SessionContext, input: Arc<dyn RAProofPlan>) -> Self {
        todo!()
    }
}
impl RAProofPlan for DistinctNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "DistinctNode"
    }

    fn children(&self) -> Vec<&Arc<dyn RAProofPlan>> {
        vec![&self.input]
    }

    fn relative_plan(&self) -> LogicalPlan {
        todo!()
    }

    fn absolute_plan(&self) -> LogicalPlan {
        todo!()
    }
}

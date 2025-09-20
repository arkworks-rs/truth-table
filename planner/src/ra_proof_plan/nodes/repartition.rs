use std::sync::Arc;

use datafusion::prelude::SessionContext;

use crate::ra_proof_plan::RAProofPlan;

pub struct RepartitionNode {
    pub input: Arc<dyn RAProofPlan>,
}

impl RepartitionNode {
    pub fn new(ctx: &SessionContext, input: Arc<dyn RAProofPlan>) -> Self {
        todo!()
    }
}

impl RAProofPlan for RepartitionNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "RepartitionNode"
    }

    fn children(&self) -> Vec<&Arc<dyn RAProofPlan>> {
        vec![&self.input]
    }

    fn relative_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }

    fn absolute_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }
}

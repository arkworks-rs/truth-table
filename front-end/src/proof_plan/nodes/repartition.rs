use std::sync::Arc;

use datafusion::prelude::SessionContext;

use crate::proof_plan::ProofPlan;

pub struct RepartitionNode {
    pub input: Arc<dyn ProofPlan>,
}

impl RepartitionNode {
    pub fn new(ctx: &SessionContext, input: Arc<dyn ProofPlan>) -> Self {
        todo!()
    }
}

impl ProofPlan for RepartitionNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "RepartitionNode"
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        vec![&self.input]
    }

    fn relative_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }

    fn absolute_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }
}

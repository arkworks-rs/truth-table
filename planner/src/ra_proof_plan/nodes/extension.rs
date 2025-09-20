use std::sync::Arc;

use datafusion::logical_expr::LogicalPlan;

use crate::ra_proof_plan::RAProofPlan;

pub struct ExtensionNode {
    pub inputs: Vec<Arc<dyn RAProofPlan>>,
}

impl ExtensionNode {
    pub fn new(inputs: Vec<Arc<dyn RAProofPlan>>) -> Self {
        todo!()
    }
}

impl RAProofPlan for ExtensionNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "ExtensionNode"
    }

    fn children(&self) -> Vec<&Arc<dyn RAProofPlan>> {
        self.inputs.iter().collect()
    }

    fn relative_plan(&self) -> LogicalPlan {
        todo!()
    }

    fn absolute_plan(&self) -> LogicalPlan {
        todo!()
    }
}

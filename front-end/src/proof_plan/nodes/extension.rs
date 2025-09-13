use std::sync::Arc;

use datafusion::logical_expr::LogicalPlan;

use crate::proof_plan::ProofPlan;

pub struct ExtensionNode {
    pub inputs: Vec<Arc<dyn ProofPlan>>,
}

impl ExtensionNode {
    pub fn new(inputs: Vec<Arc<dyn ProofPlan>>) -> Self {
        todo!()
    }
}

impl ProofPlan for ExtensionNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "ExtensionNode"
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        self.inputs.iter().collect()
    }

    fn relative_plan(&self) -> LogicalPlan {
        todo!()
    }

    fn absolute_plan(&self) -> LogicalPlan {
        todo!()
    }
}

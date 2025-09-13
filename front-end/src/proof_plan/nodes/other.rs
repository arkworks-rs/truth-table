use std::sync::Arc;

use crate::proof_plan::ProofPlan;

pub struct OtherNode {
    pub inputs: Vec<Arc<dyn ProofPlan>>,
    pub kind: String,
}
impl ProofPlan for OtherNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "OtherNode"
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        self.inputs.iter().collect()
    }

    fn relative_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }

    fn absolute_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }
}

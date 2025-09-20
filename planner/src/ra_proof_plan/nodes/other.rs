use std::sync::Arc;

use crate::ra_proof_plan::RAProofPlan;

pub struct OtherNode {
    pub inputs: Vec<Arc<dyn RAProofPlan>>,
    pub kind: String,
}
impl RAProofPlan for OtherNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "OtherNode"
    }

    fn children(&self) -> Vec<&Arc<dyn RAProofPlan>> {
        self.inputs.iter().collect()
    }

    fn relative_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }

    fn absolute_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }
}

use std::sync::Arc;

use datafusion::logical_expr::LogicalPlan;

use crate::ra_proof_plan::RAProofPlan;

pub struct ExplainNode {
    pub input: Box<dyn RAProofPlan>,
    pub absolute_plan: LogicalPlan,
}

impl ExplainNode {
    pub fn new(input: Box<dyn RAProofPlan>, absolute_plan: LogicalPlan) -> Self {
        todo!()
    }
}

impl RAProofPlan for ExplainNode {
    fn name(&self) -> &str {
        "ExplainNode"
    }

    fn children(&self) -> Vec<&Arc<dyn RAProofPlan>> {
        Vec::new()
    }

    fn absolute_plan(&self) -> LogicalPlan {
        todo!()
    }

    fn relative_plan(&self) -> LogicalPlan {
        todo!()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        todo!()
    }
}

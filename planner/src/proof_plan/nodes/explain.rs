use std::sync::Arc;

use datafusion::logical_expr::LogicalPlan;

use crate::proof_plan::ProofPlan;

pub struct ExplainNode {
    pub input: Box<dyn ProofPlan>,
    pub absolute_plan: LogicalPlan,
}

impl ExplainNode {
    pub fn new(input: Box<dyn ProofPlan>, absolute_plan: LogicalPlan) -> Self {
        todo!()
    }
}

impl ProofPlan for ExplainNode {
    fn name(&self) -> &str {
        "ExplainNode"
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
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

use std::sync::Arc;

use datafusion::prelude::SessionContext;

use crate::ra_proof_plan::RAProofPlan;

pub struct UnionNode {
    pub inputs: Vec<Arc<dyn RAProofPlan>>,
}

impl UnionNode {
    pub fn new(ctx: &SessionContext, inputs: Vec<Arc<dyn RAProofPlan>>) -> Self {
        todo!()
    }
}

impl RAProofPlan for UnionNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "UnionNode"
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

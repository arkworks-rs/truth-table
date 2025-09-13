use std::sync::Arc;

use datafusion::prelude::SessionContext;

use crate::proof_plan::ProofPlan;

pub struct UnionNode {
    pub inputs: Vec<Arc<dyn ProofPlan>>,
}

impl UnionNode {
    pub fn new(ctx: &SessionContext, inputs: Vec<Arc<dyn ProofPlan>>) -> Self {
        todo!()
    }
}

impl ProofPlan for UnionNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "UnionNode"
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

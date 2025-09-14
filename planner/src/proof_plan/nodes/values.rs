use std::sync::Arc;

use datafusion::prelude::SessionContext;

use crate::proof_plan::ProofPlan;

pub struct ValuesNode;
impl ValuesNode {
    pub fn new(ctx: &SessionContext) -> Self {
        ValuesNode
    }
}
impl ProofPlan for ValuesNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "ValuesNode"
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        Vec::new()
    }

    fn relative_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }

    fn absolute_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }
}

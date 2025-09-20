use crate::ra_proof_plan::RAProofPlan;
use datafusion::{logical_expr as df, prelude::SessionContext};
use std::sync::Arc;

pub struct SubqueryAliasNode {
    pub alias: String,
    pub input: Arc<dyn RAProofPlan>,
}

impl SubqueryAliasNode {
    pub fn new(ctx: &SessionContext, alias: String, input: Arc<dyn RAProofPlan>) -> Self {
        todo!()
    }
}

impl RAProofPlan for SubqueryAliasNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "SubqueryAliasNode"
    }

    fn children(&self) -> Vec<&Arc<dyn RAProofPlan>> {
        vec![&self.input]
    }

    fn relative_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }

    fn absolute_plan(&self) -> df::LogicalPlan {
        todo!()
    }
}

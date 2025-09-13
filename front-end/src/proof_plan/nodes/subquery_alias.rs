use crate::proof_plan::ProofPlan;
use datafusion::{logical_expr as df, prelude::SessionContext};
use std::sync::Arc;

pub struct SubqueryAliasNode {
    pub alias: String,
    pub input: Arc<dyn ProofPlan>,
}

impl SubqueryAliasNode {
    pub fn new(ctx: &SessionContext, alias: String, input: Arc<dyn ProofPlan>) -> Self {
        todo!()
    }
}

impl ProofPlan for SubqueryAliasNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "SubqueryAliasNode"
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        vec![&self.input]
    }

    fn relative_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }

    fn absolute_plan(&self) -> df::LogicalPlan {
        todo!()
    }
}

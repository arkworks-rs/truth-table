use std::sync::Arc;

use datafusion::{logical_expr::Subquery, prelude::SessionContext};

use crate::proof_plan::ProofPlan;

pub struct SubqueryNode {
    pub input: Arc<dyn ProofPlan>,
}

impl SubqueryNode {
    pub fn new(ctx: &SessionContext, input: Arc<dyn ProofPlan>) -> Self {
        todo!()
    }
}

impl ProofPlan for SubqueryNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "SubqueryNode"
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        vec![&self.input]
    }

    fn relative_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }

    fn absolute_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }
}

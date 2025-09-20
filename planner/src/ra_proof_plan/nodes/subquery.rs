use std::sync::Arc;

use datafusion::{logical_expr::Subquery, prelude::SessionContext};

use crate::ra_proof_plan::RAProofPlan;

pub struct SubqueryNode {
    pub input: Arc<dyn RAProofPlan>,
}

impl SubqueryNode {
    pub fn new(ctx: &SessionContext, input: Arc<dyn RAProofPlan>) -> Self {
        todo!()
    }
}

impl RAProofPlan for SubqueryNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "SubqueryNode"
    }

    fn children(&self) -> Vec<&Arc<dyn RAProofPlan>> {
        vec![&self.input]
    }

    fn relative_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }

    fn absolute_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }
}

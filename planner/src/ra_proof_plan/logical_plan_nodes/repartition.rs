use std::{collections::HashMap, sync::Arc};

use datafusion::prelude::SessionContext;

use crate::ra_proof_plan::ProofPlan;

pub struct RepartitionNode {
    pub input: Arc<dyn ProofPlan>,
}

impl RepartitionNode {
    pub fn new(ctx: &SessionContext, input: Arc<dyn ProofPlan>) -> Self {
        todo!()
    }
}

impl ProofPlan for RepartitionNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        vec![&self.input]
    }

    fn witness_generation_plans(&self) -> HashMap<String, datafusion::logical_expr::LogicalPlan> {
        todo!()
    }
}

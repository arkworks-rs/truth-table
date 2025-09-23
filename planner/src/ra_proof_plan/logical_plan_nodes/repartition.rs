use std::{collections::HashMap, sync::Arc};

use datafusion::prelude::SessionContext;

use crate::ra_proof_plan::ProofPlan;

pub struct RepartitionNode {
    pub input: Arc<dyn ProofPlan>,
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

    fn from_logical_plan(ctx: &SessionContext, plan: datafusion::logical_expr::LogicalPlan) -> Self
    where
        Self: Sized,
    {
        todo!()
    }
}

use std::{collections::HashMap, sync::Arc};

use crate::ra_proof_plan::ProofPlan;
use datafusion::{logical_expr as df, prelude::SessionContext};

pub struct WindowNode {
    pub window_expr: Vec<Arc<dyn ProofPlan>>,
    pub input: Arc<dyn ProofPlan>,
}

impl ProofPlan for WindowNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        vec![&self.input]
    }

    fn witness_generation_plans(&self) -> HashMap<String, df::LogicalPlan> {
        todo!()
    }

    fn from_logical_plan(ctx: &SessionContext, plan: df::LogicalPlan) -> Self
    where
        Self: Sized,
    {
        todo!()
    }
}

use std::{collections::HashMap, sync::Arc};

use datafusion::{logical_expr::LogicalPlan, prelude::SessionContext};

use crate::ra_proof_plan::ProofPlan;

pub struct AnalyzeNode {
    pub input: Arc<dyn ProofPlan>,
}

impl AnalyzeNode {
    pub fn new(ctx: &mut SessionContext, input: Arc<dyn ProofPlan>) -> Self {
        todo!()
    }
}

impl ProofPlan for AnalyzeNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        vec![&self.input]
    }

    fn witness_generation_plans(&self) -> HashMap<String, LogicalPlan> {
        todo!()
    }
}

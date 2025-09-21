use std::{collections::HashMap, sync::Arc};

use datafusion::logical_expr::LogicalPlan;

use crate::ra_proof_plan::ProofPlan;

pub struct ExplainNode {
    pub input: Box<dyn ProofPlan>,
    pub absolute_plan: LogicalPlan,
}

impl ExplainNode {
    pub fn new(input: Box<dyn ProofPlan>, absolute_plan: LogicalPlan) -> Self {
        todo!()
    }
}

impl ProofPlan for ExplainNode {
    fn as_any(&self) -> &dyn std::any::Any {
        todo!()
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        Vec::new()
    }

    fn witness_generation_plans(&self) -> HashMap<String, LogicalPlan> {
        todo!()
    }
}

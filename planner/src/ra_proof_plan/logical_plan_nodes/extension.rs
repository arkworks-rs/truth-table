use std::{collections::HashMap, sync::Arc};

use datafusion::logical_expr::LogicalPlan;

use crate::ra_proof_plan::ProofPlan;

pub struct ExtensionNode {
    pub inputs: Vec<Arc<dyn ProofPlan>>,
}

impl ExtensionNode {
    pub fn new(inputs: Vec<Arc<dyn ProofPlan>>) -> Self {
        todo!()
    }
}

impl ProofPlan for ExtensionNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        self.inputs.iter().collect()
    }

    fn witness_generation_plans(&self) -> HashMap<String, LogicalPlan> {
        todo!()
    }
}

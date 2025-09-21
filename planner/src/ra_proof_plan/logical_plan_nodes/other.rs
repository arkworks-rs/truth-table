use std::{collections::HashMap, sync::Arc};

use crate::ra_proof_plan::ProofPlan;

pub struct OtherNode {
    pub inputs: Vec<Arc<dyn ProofPlan>>,
    pub kind: String,
}
impl ProofPlan for OtherNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        self.inputs.iter().collect()
    }
    fn witness_generation_plans(&self) -> HashMap<String, datafusion::logical_expr::LogicalPlan> {
        todo!()
    }
}

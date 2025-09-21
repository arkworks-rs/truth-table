use std::{collections::HashMap, sync::Arc};

use datafusion::prelude::SessionContext;

use crate::ra_proof_plan::ProofPlan;

pub struct UnionNode {
    pub inputs: Vec<Arc<dyn ProofPlan>>,
}

impl UnionNode {
    pub fn new(ctx: &SessionContext, inputs: Vec<Arc<dyn ProofPlan>>) -> Self {
        todo!()
    }
}

impl ProofPlan for UnionNode {
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

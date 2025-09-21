use std::{collections::HashMap, sync::Arc};

use datafusion::prelude::SessionContext;

use crate::ra_proof_plan::ProofPlan;

pub struct ValuesNode;
impl ValuesNode {
    pub fn new(ctx: &SessionContext) -> Self {
        ValuesNode
    }
}
impl ProofPlan for ValuesNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        Vec::new()
    }

    fn witness_generation_plans(&self) -> HashMap<String, datafusion::logical_expr::LogicalPlan> {
        todo!()
    }
}

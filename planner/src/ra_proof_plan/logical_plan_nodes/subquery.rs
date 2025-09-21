use std::{collections::HashMap, sync::Arc};

use datafusion::{logical_expr::Subquery, prelude::SessionContext};

use crate::ra_proof_plan::ProofPlan;

pub struct SubqueryNode {
    pub input: Arc<dyn ProofPlan>,
}

impl SubqueryNode {
    pub fn new(ctx: &SessionContext, input: Arc<dyn ProofPlan>) -> Self {
        todo!()
    }
}

impl ProofPlan for SubqueryNode {
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

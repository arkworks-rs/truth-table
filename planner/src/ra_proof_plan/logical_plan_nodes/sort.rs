use std::{collections::HashMap, sync::Arc};

use crate::ra_proof_plan::ProofPlan;
use datafusion::{logical_expr as df, prelude::SessionContext};

pub struct SortNode {
    pub sort_expr: Vec<(Arc<dyn ProofPlan>, bool, bool)>,
    pub fetch: Option<usize>,
    pub input: Arc<dyn ProofPlan>,
}

impl SortNode {
    pub fn new(
        ctx: SessionContext,
        sort_expr: Vec<(Arc<dyn ProofPlan>, bool, bool)>,
        fetch: Option<usize>,
        input: Arc<dyn ProofPlan>,
    ) -> Self {
        todo!()
    }
}

impl ProofPlan for SortNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        vec![&self.input]
    }

    fn witness_generation_plans(&self) -> HashMap<String, df::LogicalPlan> {
        todo!()
    }
}

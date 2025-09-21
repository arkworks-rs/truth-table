use std::{collections::HashMap, sync::Arc};

use crate::ra_proof_plan::ProofPlan;
use datafusion::{
    logical_expr::{self as df, Join},
    prelude::SessionContext,
};

pub struct JoinNode {
    pub left: Arc<dyn ProofPlan>,
    pub right: Arc<dyn ProofPlan>,
    pub on: Vec<(Arc<dyn ProofPlan>, Arc<dyn ProofPlan>)>,
    pub filter: Option<Arc<dyn ProofPlan>>,
    pub join_type: df::JoinType,
    pub null_equals_null: bool,
}

impl JoinNode {
    pub fn new(
        ctx: &SessionContext,
        left: Arc<dyn ProofPlan>,
        right: Arc<dyn ProofPlan>,
        on: Vec<(Arc<dyn ProofPlan>, Arc<dyn ProofPlan>)>,
        filter: Option<Arc<dyn ProofPlan>>,
        join_type: df::JoinType,
        null_equals_null: bool,
    ) -> Self {
        todo!()
    }
}

impl ProofPlan for JoinNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        vec![&self.left, &self.right]
    }

    fn witness_generation_plans(&self) -> HashMap<String, df::LogicalPlan> {
        todo!()
    }
}

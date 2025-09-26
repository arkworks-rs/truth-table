use datafusion::{
    logical_expr::{self as df, LogicalPlan, LogicalPlanBuilder},
    prelude::SessionContext,
};
use std::{collections::HashMap, sync::Arc};

use crate::nodes::{ProofPlan, ProofPlanNodeId};

pub struct LimitNode {
    pub skip: Option<Arc<dyn ProofPlan>>,
    pub fetch: Option<Arc<dyn ProofPlan>>,
    pub input: Arc<dyn ProofPlan>,
    pub node_id: ProofPlanNodeId,
    pub witness_generation_plans: HashMap<String, df::LogicalPlan>,
}

impl ProofPlan for LimitNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        vec![&self.input]
    }

    fn node_id(&self) -> ProofPlanNodeId {
        self.node_id.clone()
    }

    fn witness_generation_plans(&self) -> HashMap<String, df::LogicalPlan> {
        self.witness_generation_plans.clone()
    }

    fn from_logical_plan(ctx: &SessionContext, plan: LogicalPlan) -> Self
    where
        Self: Sized,
    {
        todo!()
    }

    fn piop_plan(&self) {
        todo!()
    }
}

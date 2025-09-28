use datafusion::{
    logical_expr::{self as df, LogicalPlan, LogicalPlanBuilder},
    prelude::SessionContext,
};
use std::{collections::HashMap, sync::Arc};

use crate::trees::proof_tree::nodes::{ProverNode, ProverNodeNodeId};

pub struct LimitNode {
    pub skip: Option<Arc<dyn ProverNode>>,
    pub fetch: Option<Arc<dyn ProverNode>>,
    pub input: Arc<dyn ProverNode>,
    pub node_id: ProverNodeNodeId,
    pub hint_generation_plans: HashMap<String, df::LogicalPlan>,
}

impl ProverNode for LimitNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode>> {
        vec![&self.input]
    }

    fn node_id(&self) -> ProverNodeNodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(&self) -> HashMap<String, df::LogicalPlan> {
        self.hint_generation_plans.clone()
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

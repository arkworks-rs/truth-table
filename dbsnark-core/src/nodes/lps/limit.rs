use datafusion::{
    logical_expr::{self as df, LogicalPlan, LogicalPlanBuilder},
    prelude::SessionContext,
};
use std::{collections::HashMap, sync::Arc};

use crate::nodes::{ProverNode, ProverNodeNodeId};

pub struct LimitNode {
    pub skip: Option<Arc<dyn ProverNode>>,
    pub fetch: Option<Arc<dyn ProverNode>>,
    pub input: Arc<dyn ProverNode>,
    pub node_id: ProverNodeNodeId,
    pub proof_trees: HashMap<String, df::LogicalPlan>,
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

    fn proof_trees(&self) -> HashMap<String, df::LogicalPlan> {
        self.proof_trees.clone()
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

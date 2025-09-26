use std::{collections::HashMap, sync::Arc};

use datafusion::{logical_expr as df, prelude::SessionContext};

use crate::nodes::ProverNode;

pub struct SortNode {
    pub sort_expr: Vec<(Arc<dyn ProverNode>, bool, bool)>,
    pub fetch: Option<usize>,
    pub input: Arc<dyn ProverNode>,
}

impl ProverNode for SortNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode>> {
        vec![&self.input]
    }

    fn proof_trees(&self) -> HashMap<String, df::LogicalPlan> {
        todo!()
    }

    fn from_logical_plan(ctx: &SessionContext, plan: df::LogicalPlan) -> Self
    where
        Self: Sized,
    {
        todo!()
    }

    fn node_id(&self) -> crate::nodes::ProverNodeNodeId {
        todo!()
    }

    fn piop_plan(&self) {
        todo!()
    }
}

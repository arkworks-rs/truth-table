use std::{collections::HashMap, sync::Arc};

use datafusion::prelude::SessionContext;

use crate::nodes::ProverNode;

pub struct UnionNode {
    pub inputs: Vec<Arc<dyn ProverNode>>,
}

impl ProverNode for UnionNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode>> {
        self.inputs.iter().collect()
    }

    fn proof_trees(&self) -> HashMap<String, datafusion::logical_expr::LogicalPlan> {
        todo!()
    }

    fn from_logical_plan(ctx: &SessionContext, plan: datafusion::logical_expr::LogicalPlan) -> Self
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

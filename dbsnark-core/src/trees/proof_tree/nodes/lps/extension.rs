use std::{collections::HashMap, sync::Arc};

use datafusion::{logical_expr::LogicalPlan, prelude::SessionContext};

use crate::trees::proof_tree::nodes::ProverNode;

pub struct ExtensionNode {
    pub inputs: Vec<Arc<dyn ProverNode>>,
}

impl ProverNode for ExtensionNode {
    fn from_logical_plan(ctx: &SessionContext, plan: LogicalPlan) -> Self
    where
        Self: Sized,
    {
        todo!()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode>> {
        self.inputs.iter().collect()
    }

    fn hint_generation_plans(&self) -> HashMap<String, LogicalPlan> {
        todo!()
    }

    fn node_id(&self) -> crate::trees::proof_tree::nodes::ProverNodeNodeId {
        todo!()
    }

    fn piop_plan(&self) {
        todo!()
    }
}

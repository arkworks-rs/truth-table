use std::{collections::HashMap, sync::Arc};

use datafusion::{logical_expr::LogicalPlan, prelude::SessionContext};

use crate::trees::proof_tree::nodes::ProverNode;

pub struct ExplainNode {
    pub input: Box<dyn ProverNode>,
    pub output_plan: LogicalPlan,
}

impl ProverNode for ExplainNode {
    fn from_logical_plan(ctx: &SessionContext, plan: LogicalPlan) -> Self
    where
        Self: Sized,
    {
        todo!()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        todo!()
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode>> {
        Vec::new()
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

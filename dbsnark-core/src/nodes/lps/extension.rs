use std::{collections::HashMap, sync::Arc};

use datafusion::{logical_expr::LogicalPlan, prelude::SessionContext};

use crate::nodes::ProofPlan;

pub struct ExtensionNode {
    pub inputs: Vec<Arc<dyn ProofPlan>>,
}

impl ProofPlan for ExtensionNode {
    fn from_logical_plan(ctx: &SessionContext, plan: LogicalPlan) -> Self
    where
        Self: Sized,
    {
        todo!()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        self.inputs.iter().collect()
    }

    fn witness_generation_plans(&self) -> HashMap<String, LogicalPlan> {
        todo!()
    }

    fn node_id(&self) -> crate::nodes::ProofPlanNodeId {
        todo!()
    }

    fn piop_plan(&self) {
        todo!()
    }
}

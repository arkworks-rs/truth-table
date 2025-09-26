use std::{collections::HashMap, sync::Arc};

use datafusion::{logical_expr::LogicalPlan, prelude::SessionContext};

use crate::nodes::ProofPlan;

pub struct ExplainNode {
    pub input: Box<dyn ProofPlan>,
    pub output_plan: LogicalPlan,
}

impl ProofPlan for ExplainNode {
    fn from_logical_plan(ctx: &SessionContext, plan: LogicalPlan) -> Self
    where
        Self: Sized,
    {
        todo!()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        todo!()
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        Vec::new()
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

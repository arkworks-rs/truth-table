use std::{collections::HashMap, sync::Arc};

use datafusion::{logical_expr::LogicalPlan, prelude::SessionContext};

use crate::nodes::ProofPlan;

pub struct AnalyzeNode {
    pub input: Arc<dyn ProofPlan>,
}

impl ProofPlan for AnalyzeNode {
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
        vec![&self.input]
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

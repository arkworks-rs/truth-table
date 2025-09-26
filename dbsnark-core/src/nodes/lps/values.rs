use std::{collections::HashMap, sync::Arc};

use datafusion::prelude::SessionContext;

use crate::nodes::ProofPlan;

pub struct ValuesNode;

impl ProofPlan for ValuesNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        Vec::new()
    }

    fn witness_generation_plans(&self) -> HashMap<String, datafusion::logical_expr::LogicalPlan> {
        todo!()
    }

    fn from_logical_plan(ctx: &SessionContext, plan: datafusion::logical_expr::LogicalPlan) -> Self
    where
        Self: Sized,
    {
        todo!()
    }

    fn node_id(&self) -> crate::nodes::ProofPlanNodeId {
        todo!()
    }

    fn piop_plan(&self) {
        todo!()
    }
}

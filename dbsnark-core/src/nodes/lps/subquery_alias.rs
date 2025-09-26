use datafusion::{logical_expr as df, prelude::SessionContext};
use std::{collections::HashMap, sync::Arc};

use crate::nodes::ProofPlan;

pub struct SubqueryAliasNode {
    pub alias: String,
    pub input: Arc<dyn ProofPlan>,
}
impl ProofPlan for SubqueryAliasNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        vec![&self.input]
    }

    fn witness_generation_plans(&self) -> HashMap<String, df::LogicalPlan> {
        todo!()
    }

    fn from_logical_plan(ctx: &SessionContext, plan: df::LogicalPlan) -> Self
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

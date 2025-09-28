use datafusion::{logical_expr as df, prelude::SessionContext};
use std::{collections::HashMap, sync::Arc};

use crate::trees::proof_tree::nodes::ProverNode;

pub struct SubqueryAliasNode {
    pub alias: String,
    pub input: Arc<dyn ProverNode>,
}
impl ProverNode for SubqueryAliasNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode>> {
        vec![&self.input]
    }

    fn hint_generation_plans(&self) -> HashMap<String, df::LogicalPlan> {
        todo!()
    }

    fn from_logical_plan(ctx: &SessionContext, plan: df::LogicalPlan) -> Self
    where
        Self: Sized,
    {
        todo!()
    }

    fn node_id(&self) -> crate::trees::proof_tree::nodes::ProverNodeNodeId {
        todo!()
    }

    fn piop_plan(&self) {
        todo!()
    }
}

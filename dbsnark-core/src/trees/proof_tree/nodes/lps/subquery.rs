use std::{collections::HashMap, sync::Arc};

use datafusion::{logical_expr::Subquery, prelude::SessionContext};

use crate::trees::proof_tree::nodes::ProverNode;

pub struct SubqueryNode {
    pub input: Arc<dyn ProverNode>,
}

impl ProverNode for SubqueryNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode>> {
        vec![&self.input]
    }

    fn hint_generation_plans(&self) -> HashMap<String, datafusion::logical_expr::LogicalPlan> {
        todo!()
    }

    fn from_logical_plan(ctx: &SessionContext, plan: datafusion::logical_expr::LogicalPlan) -> Self
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

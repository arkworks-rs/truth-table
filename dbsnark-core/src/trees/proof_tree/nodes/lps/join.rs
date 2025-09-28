use std::{collections::HashMap, sync::Arc};

use datafusion::{
    logical_expr::{self as df, Join},
    prelude::SessionContext,
};

use crate::trees::proof_tree::nodes::ProverNode;

pub struct JoinNode {
    pub left: Arc<dyn ProverNode>,
    pub right: Arc<dyn ProverNode>,
    pub on: Vec<(Arc<dyn ProverNode>, Arc<dyn ProverNode>)>,
    pub filter: Option<Arc<dyn ProverNode>>,
    pub join_type: df::JoinType,
    pub null_equals_null: bool,
}

impl ProverNode for JoinNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode>> {
        vec![&self.left, &self.right]
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

// TODO: Compute the following witnesses:
// pub left_key_support: ArithCol<F, MvPCS, UvPCS>,
// pub right_key_support: ArithCol<F, MvPCS, UvPCS>,
// pub out_key_support: ArithCol<F, MvPCS, UvPCS>,
// pub all_key_support: ArithCol<F, MvPCS, UvPCS>,
// pub join_left_source: ArithCol<F, MvPCS, UvPCS>,
// pub join_right_source: ArithCol<F, MvPCS, UvPCS>,
// pub right_table_multiplicity: TrackedPoly<F, MvPCS, UvPCS>,
// pub left_table_multiplicity: TrackedPoly<F, MvPCS, UvPCS>,

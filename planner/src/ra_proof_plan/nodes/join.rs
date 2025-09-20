use std::sync::Arc;

use crate::ra_proof_plan::RAProofPlan;
use datafusion::{
    logical_expr::{self as df, Join},
    prelude::SessionContext,
};

pub struct JoinNode {
    pub left: Arc<dyn RAProofPlan>,
    pub right: Arc<dyn RAProofPlan>,
    pub on: Vec<(df::Expr, df::Expr)>,
    pub filter: Option<df::Expr>,
    pub join_type: df::JoinType,
    pub null_equals_null: bool,
}

impl JoinNode {
    pub fn new(
        ctx: &SessionContext,
        left: Arc<dyn RAProofPlan>,
        right: Arc<dyn RAProofPlan>,
        on: Vec<(df::Expr, df::Expr)>,
        filter: Option<df::Expr>,
        join_type: df::JoinType,
        null_equals_null: bool,
    ) -> Self {
        todo!()
    }
}

impl RAProofPlan for JoinNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "JoinNode"
    }

    fn children(&self) -> Vec<&Arc<dyn RAProofPlan>> {
        vec![&self.left, &self.right]
    }

    fn relative_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }

    fn absolute_plan(&self) -> df::LogicalPlan {
        todo!()
    }
}

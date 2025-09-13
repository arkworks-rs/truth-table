use std::sync::Arc;

use crate::proof_plan::ProofPlan;
use datafusion::{
    logical_expr::{self as df, Join},
    prelude::SessionContext,
};

pub struct JoinNode {
    pub left: Arc<dyn ProofPlan>,
    pub right: Arc<dyn ProofPlan>,
    pub on: Vec<(df::Expr, df::Expr)>,
    pub filter: Option<df::Expr>,
    pub join_type: df::JoinType,
    pub null_equals_null: bool,

}

impl JoinNode {
    pub fn new(
        ctx: &SessionContext,
        left: Arc<dyn ProofPlan>,
        right: Arc<dyn ProofPlan>,
        on: Vec<(df::Expr, df::Expr)>,
        filter: Option<df::Expr>,
        join_type: df::JoinType,
        null_equals_null: bool,
    ) -> Self {
        todo!()
    }
}

impl ProofPlan for JoinNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "JoinNode"
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        vec![&self.left, &self.right]
    }

    fn relative_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        todo!()
    }
    
    fn absolute_plan(&self) -> df::LogicalPlan {
        todo!()
    }
}

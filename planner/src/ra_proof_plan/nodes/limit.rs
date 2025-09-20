use crate::ra_proof_plan::RAProofPlan;
use datafusion::{
    logical_expr::{self as df, LogicalPlan, LogicalPlanBuilder},
    prelude::SessionContext,
};
use std::sync::Arc;

pub struct LimitNode {
    pub skip: Option<Box<df::Expr>>,
    pub fetch: Option<Box<df::Expr>>,
    pub input: Arc<dyn RAProofPlan>,
    pub relative_plan: df::LogicalPlan,
    pub absolute_plan: df::LogicalPlan,
}

impl LimitNode {
    /// Build a relative plan by applying a logical Limit (skip/fetch).
    /// Note: This uses DataFusion's Limit operator which reduces row count.
    /// Columns are preserved as-is.
    pub fn make_relative_plan(
        input_plan: LogicalPlan,
        skip: Option<Box<df::Expr>>,
        fetch: Option<Box<df::Expr>>,
    ) -> LogicalPlan {
        todo!()
    }

    pub fn new(
        ctx: &SessionContext,
        skip: Option<Box<df::Expr>>,
        fetch: Option<Box<df::Expr>>,
        input: Arc<dyn RAProofPlan>,
    ) -> Self {
        let input_rel = input.relative_plan();
        let relative_plan = Self::make_relative_plan(input_rel, skip.clone(), fetch.clone());
        let absolute_plan = ctx.state().optimize(&relative_plan).unwrap();
        Self {
            skip,
            fetch,
            input,
            relative_plan,
            absolute_plan,
        }
    }
}

impl RAProofPlan for LimitNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "LimitNode"
    }

    fn children(&self) -> Vec<&Arc<dyn RAProofPlan>> {
        vec![&self.input]
    }

    fn relative_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        self.relative_plan.clone()
    }

    fn absolute_plan(&self) -> df::LogicalPlan {
        self.absolute_plan.clone()
    }
}

use std::sync::Arc;

use crate::ra_proof_plan::RAProofPlan;
use datafusion::{
    logical_expr::LogicalPlan,
    prelude::{Expr, SessionContext},
};
pub struct AggregateNode {
    pub group_expr: Vec<Expr>,
    pub aggr_expr: Vec<Expr>,
    pub input: Arc<dyn RAProofPlan>,
    pub relative_plan: LogicalPlan,
    pub absolute_plan: LogicalPlan,
}

impl AggregateNode {
    pub fn make_relative_plan(
        group_expr: Vec<Expr>,
        aggr_expr: Vec<Expr>,
        input: Arc<dyn RAProofPlan>,
    ) -> LogicalPlan {
        todo!()
    }

    pub fn new(
        ctx: &mut SessionContext,
        group_expr: Vec<Expr>,
        aggr_expr: Vec<Expr>,
        input: Arc<dyn RAProofPlan>,
    ) -> Self {
        let relative_plan =
            Self::make_relative_plan(group_expr.clone(), aggr_expr.clone(), input.clone());
        AggregateNode {
            group_expr,
            aggr_expr,
            input,
            relative_plan: relative_plan.clone(),
            absolute_plan: ctx.state().optimize(&relative_plan).unwrap(),
        }
    }
}

impl RAProofPlan for AggregateNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "AggregateNode"
    }

    fn children(&self) -> Vec<&Arc<dyn RAProofPlan>> {
        vec![&self.input]
    }

    fn relative_plan(&self) -> LogicalPlan {
        self.relative_plan.clone()
    }

    fn absolute_plan(&self) -> LogicalPlan {
        self.absolute_plan.clone()
    }
}

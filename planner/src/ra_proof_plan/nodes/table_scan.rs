use crate::ra_proof_plan::RAProofPlan;
use datafusion::{
    logical_expr::{self as df, LogicalPlan},
    prelude::SessionContext,
};
use std::sync::Arc;
/// Proof node representing a base table scan.
///
/// - `plan`: the original DataFusion TableScan logical plan
/// - `absolute_plan`: the unrolled plan beginning at this scan and projecting
///   an additional `activator=true` column
pub struct TableScanNode {
    pub plan: LogicalPlan,
    pub relative_plan: LogicalPlan,
    pub absolute_plan: LogicalPlan,
}

impl TableScanNode {
    // Build a relative plan identical to the original scan (no added columns,
    // no padding). Assumes upstream data already contains any required
    // bookkeeping columns (e.g., `activator`).
    pub fn make_relative_plan(plan: LogicalPlan) -> df::LogicalPlan {
        plan
    }

    pub fn new(ctx: &SessionContext, plan: df::LogicalPlan) -> Self {
        let relative_plan = Self::make_relative_plan(plan.clone());
        let absolute_plan = ctx.state().optimize(&relative_plan).unwrap();
        TableScanNode {
            plan,
            relative_plan,
            absolute_plan,
        }
    }
}

impl RAProofPlan for TableScanNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn name(&self) -> &str {
        "TableScanNode"
    }

    fn children(&self) -> Vec<&Arc<dyn RAProofPlan>> {
        Vec::new()
    }

    fn relative_plan(&self) -> datafusion::logical_expr::LogicalPlan {
        self.relative_plan.clone()
    }

    fn absolute_plan(&self) -> df::LogicalPlan {
        self.absolute_plan.clone()
    }
}

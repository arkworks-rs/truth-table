use crate::ra_proof_plan::{ProofPlan, ProofPlanNodeId};
use datafusion::{
    logical_expr::{self as df, LogicalPlan},
    prelude::SessionContext,
};
use std::{collections::HashMap, sync::Arc};

/// Proof node representing a base table scan.
///
/// - `plan`: the original DataFusion TableScan logical plan
/// - witness plans include both the relative ("output_plan") plan and the
///   original ("relative_output") scan plan.
pub struct TableScanNode {
    pub plan: LogicalPlan,
    pub node_id: ProofPlanNodeId,
    pub witness_generation_plans: HashMap<String, LogicalPlan>,
}

impl TableScanNode {
    // Build a relative plan identical to the original scan (no added columns,
    // no padding). Assumes upstream data already contains any required
    // bookkeeping columns (e.g., `activator`).
    pub fn build_output_plan(plan: LogicalPlan) -> df::LogicalPlan {
        plan
    }
}

impl ProofPlan for TableScanNode {
    fn from_logical_plan(ctx: &SessionContext, plan: LogicalPlan) -> Self
    where
        Self: Sized,
    {
        let output_plan = Self::build_output_plan(plan.clone());
        let mut witness_generation_plans = HashMap::new();
        witness_generation_plans.insert("output_plan".to_string(), output_plan.clone());
        Self {
            plan: plan.clone(),
            node_id: ProofPlanNodeId::LogicalPlan(plan),
            witness_generation_plans,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        Vec::new()
    }

    fn node_id(&self) -> ProofPlanNodeId {
        self.node_id.clone()
    }

    fn witness_generation_plans(&self) -> HashMap<String, df::LogicalPlan> {
        self.witness_generation_plans.clone()
    }
}

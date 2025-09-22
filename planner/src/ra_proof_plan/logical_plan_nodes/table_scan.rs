use crate::ra_proof_plan::{ProofPlan, ProofPlanNodeType};
use datafusion::{
    logical_expr::{self as df, LogicalPlan},
    prelude::SessionContext,
};
use std::{collections::HashMap, sync::Arc};

/// Proof node representing a base table scan.
///
/// - `plan`: the original DataFusion TableScan logical plan
/// - witness plans include both the relative ("absolute_output") plan and the
///   original ("relative_output") scan plan.
pub struct TableScanNode {
    pub plan: LogicalPlan,
    pub node_type: ProofPlanNodeType,
    pub witness_generation_plans: HashMap<String, LogicalPlan>,
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
        let mut witness_generation_plans = HashMap::new();
        witness_generation_plans.insert("absolute_output".to_string(), relative_plan.clone());
        TableScanNode {
            plan: plan.clone(),
            node_type: ProofPlanNodeType::LogicalPlan(plan),
            witness_generation_plans,
        }
    }
}

impl ProofPlan for TableScanNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        Vec::new()
    }

    fn node_type(&self) -> ProofPlanNodeType {
        self.node_type.clone()
    }

    fn witness_generation_plans(&self) -> HashMap<String, df::LogicalPlan> {
        self.witness_generation_plans.clone()
    }
}

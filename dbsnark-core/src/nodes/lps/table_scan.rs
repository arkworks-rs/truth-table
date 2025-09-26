use datafusion::{
    logical_expr::{self as df, LogicalPlan},
    prelude::SessionContext,
};
use std::{collections::HashMap, sync::Arc};

use crate::nodes::{ProverNode, ProverNodeNodeId};

/// Proof node representing a base table scan.
///
/// - `plan`: the original DataFusion TableScan logical plan
/// - witness plans include both the relative ("output_plan") plan and the
///   original ("relative_output") scan plan.
pub struct TableScanNode {
    pub plan: LogicalPlan,
    pub node_id: ProverNodeNodeId,
    pub proof_trees: HashMap<String, LogicalPlan>,
}

impl TableScanNode {
    // Build a relative plan identical to the original scan (no added columns,
    // no padding). Assumes upstream data already contains any required
    // bookkeeping columns (e.g., `activator`).
    pub fn build_output_plan(plan: LogicalPlan) -> df::LogicalPlan {
        plan
    }
}

impl ProverNode for TableScanNode {
    fn from_logical_plan(ctx: &SessionContext, plan: LogicalPlan) -> Self
    where
        Self: Sized,
    {
        let output_plan = Self::build_output_plan(plan.clone());
        let mut proof_trees = HashMap::new();
        proof_trees.insert("output_plan".to_string(), output_plan.clone());
        Self {
            plan: plan.clone(),
            node_id: ProverNodeNodeId::LP(plan),
            proof_trees,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode>> {
        Vec::new()
    }

    fn node_id(&self) -> ProverNodeNodeId {
        self.node_id.clone()
    }

    fn proof_trees(&self) -> HashMap<String, df::LogicalPlan> {
        self.proof_trees.clone()
    }

    fn piop_plan(&self) {
        todo!()
    }
}

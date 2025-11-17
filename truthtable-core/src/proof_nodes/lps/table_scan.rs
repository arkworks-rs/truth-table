use datafusion_expr::LogicalPlan;

use crate::tree::NodeId;

pub struct ProverTableScanNode {
    pub plan: LogicalPlan,
    pub node_id: NodeId,
}
pub struct VerifierTableScanNode {
    pub plan: LogicalPlan,
    pub node_id: NodeId,
}

use super::ProofNode;
use datafusion::logical_expr as df;

#[derive(Debug, Clone)]
pub struct TableScanNode;

impl ProofNode for TableScanNode {
    type LogicalCounterpart = df::TableScan;
    fn from_logical(lp: &Self::LogicalCounterpart) -> Self {
        TableScanNode
    }
    fn io_plan(lp: &Self::LogicalCounterpart) -> df::LogicalPlan {
        df::LogicalPlan::TableScan(lp.clone())
    }
}

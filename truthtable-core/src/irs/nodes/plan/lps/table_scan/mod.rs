use ark_piop::SnarkBackend;
use datafusion::dataframe::DataFrame;
use datafusion::prelude::SessionContext;
use datafusion_expr::{LogicalPlan, TableScan};

use crate::irs::nodes::hints::HintDF;

mod gadget;
#[derive(Debug)]
pub struct ProverNode {
    pub table_scan: TableScan,
}

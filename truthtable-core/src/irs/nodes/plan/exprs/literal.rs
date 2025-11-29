use std::sync::Arc;

use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion_common::{ScalarValue, Statistics};
use datafusion_expr::Expr;

use crate::irs::nodes::{NodeId, cost::ProvingCost, hints::HintDF};
#[derive(Debug)]
pub struct ProverNode {
    pub literal: ScalarValue,
    pub parent: NodeId,
}

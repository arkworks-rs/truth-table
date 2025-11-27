use std::sync::Arc;

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion_expr::Cast;

use crate::irs::tree::PlanNode;

#[derive(Clone)]
pub struct ProverCastExprNode<B> {
    cast: Cast,
    input: Arc<dyn PlanNode<B>>,
}

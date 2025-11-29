use std::sync::Arc;

use ark_ff::PrimeField;
use ark_piop::{
    SnarkBackend, arithmetic::mat_poly::{lde::LDE, mle::MLE}, pcs::PCS
};
use datafusion_expr::Cast;

use crate::irs::nodes::Node;

#[derive(Clone)]
pub struct ProverCastExprNode<B:SnarkBackend> {
    cast: Cast,
    input: Node<B>,
}

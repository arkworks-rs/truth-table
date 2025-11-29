use std::sync::Arc;

use ark_ff::PrimeField;
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion_expr::Join;

use crate::irs::nodes::Node;

#[allow(clippy::type_complexity)]
pub struct ProverJoinNode<B>
where
    B: SnarkBackend,
{
    left: Node<B>,
    right: Node<B>,
    on: Vec<(Node<B>, Node<B>)>,
    filter: Option<Node<B>>,
    join: Join,
}

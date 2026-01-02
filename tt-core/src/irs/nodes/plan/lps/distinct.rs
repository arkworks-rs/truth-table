use std::sync::Arc;

use ark_piop::SnarkBackend;
use datafusion_expr::Distinct;

use crate::irs::nodes::Node;

pub struct ProverDistinctNode<B>
where
    B: SnarkBackend,
{
    input: Node<B>,
    distinct: Distinct,
}

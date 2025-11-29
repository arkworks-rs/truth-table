use ark_piop::SnarkBackend;
use datafusion_expr::Projection;

use crate::irs::nodes::Node;

pub(super) mod hints;

pub struct ProverNode<B>
where
    B: SnarkBackend,
{
    projection: Projection,
    input: Node<B>,
    expr: Node<B>,
}


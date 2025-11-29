use ark_piop::SnarkBackend;

use datafusion_expr::Limit;

use crate::irs::nodes::Node;

pub struct ProverNode<B>
where
    B: SnarkBackend,
{
    input: Node<B>,
    limit: Limit,
}

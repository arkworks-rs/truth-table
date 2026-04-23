use ark_piop::SnarkBackend;
use datafusion_expr::Subquery;

use crate::irs::nodes::Node;
#[allow(unused)]
pub struct ProverSubqueryNode<B>
where
    B: SnarkBackend,
{
    input: Node<B>,
    subquery: Subquery,
}

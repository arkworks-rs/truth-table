use ark_piop::SnarkBackend;
use datafusion_expr::Subquery;

use std::sync::Arc;

use crate::irs::nodes::Node;

pub struct ProverSubqueryNode<B>
where
    B: SnarkBackend,
{
    input: Node<B>,
    subquery: Subquery,
}

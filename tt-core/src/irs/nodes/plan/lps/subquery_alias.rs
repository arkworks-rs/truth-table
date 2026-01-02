use ark_piop::SnarkBackend;
use datafusion_expr::SubqueryAlias;
use std::sync::Arc;

use crate::irs::nodes::Node;

pub struct ProverNode<B>
where
    B: SnarkBackend,
{
    input: Node<B>,
    subquery_alias: SubqueryAlias,
}

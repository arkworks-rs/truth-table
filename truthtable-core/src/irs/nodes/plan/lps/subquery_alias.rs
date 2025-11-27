use ark_piop::SnarkBackend;
use datafusion_expr::SubqueryAlias;
use std::sync::Arc;

use crate::irs::tree::PlanNode;

pub struct ProverSubqueryAliasNode<B>
where
    B: SnarkBackend,
{
    input: Arc<dyn PlanNode<B>>,
    subquery_alias: SubqueryAlias,
}

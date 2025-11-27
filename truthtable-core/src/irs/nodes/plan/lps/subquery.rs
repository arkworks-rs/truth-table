use ark_piop::SnarkBackend;
use datafusion_expr::Subquery;

use std::sync::Arc;

use crate::irs::tree::PlanNode;
pub struct ProverSubqueryNode<B>
where
    B: SnarkBackend,
{
    input: Arc<dyn PlanNode<B>>,
    subquery: Subquery,
}

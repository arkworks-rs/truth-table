use ark_piop::SnarkBackend;

use datafusion_expr::Limit;
use std::sync::Arc;

use crate::irs::tree::PlanNode;

pub struct ProverLimitNode<B>
where
    B: SnarkBackend,
{
    input: Arc<dyn PlanNode<B>>,
    limit: Limit,
}

use std::sync::Arc;

use ark_piop::SnarkBackend;
use datafusion_expr::Distinct;

use crate::irs::tree::PlanNode;

pub struct ProverDistinctNode<B>
where
    B: SnarkBackend,
{
    input: Arc<dyn PlanNode<B>>,
    distinct: Distinct,
}

use std::sync::Arc;

use ark_ff::PrimeField;
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion_expr::Join;

use crate::irs::tree::PlanNode;

#[allow(clippy::type_complexity)]
pub struct ProverJoinNode<B>
where
    B: SnarkBackend,
{
    left: Arc<dyn PlanNode<B>>,
    right: Arc<dyn PlanNode<B>>,
    on: Vec<(Arc<dyn PlanNode<B>>, Arc<dyn PlanNode<B>>)>,
    filter: Option<Arc<dyn PlanNode<B>>>,
    join: Join,
}

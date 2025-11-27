use std::sync::Arc;

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion_expr::Join;

use crate::nodes::{prover::ProverPlanNode, verifier::VerifierNode};

#[allow(clippy::type_complexity)]
pub struct ProverJoinNode<B>
where
B:SnarkBackend
{
    left: Arc<dyn ProverPlanNode<B>>,
    right: Arc<dyn ProverPlanNode<B>>,
    on: Vec<(
        Arc<dyn ProverPlanNode<B>>,
        Arc<dyn ProverPlanNode<B>>,
    )>,
    filter: Option<Arc<dyn ProverPlanNode<B>>>,
    join: Join,
}

#[allow(clippy::type_complexity)]
pub struct VerifierJoinNode<B>
where
B:SnarkBackend
{
    left: Arc<dyn VerifierNode<B>>,
    right: Arc<dyn VerifierNode<B>>,
    on: Vec<(
        Arc<dyn VerifierNode<B>>,
        Arc<dyn VerifierNode<B>>,
    )>,
    filter: Option<Arc<dyn VerifierNode<B>>>,
    join: Join,
}

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};

use datafusion_expr::Limit;
use std::sync::Arc;

use crate::nodes::{prover::ProverPlanNode, verifier::VerifierNode};

pub struct ProverLimitNode<B>
where
B:SnarkBackend
{
    input: Arc<dyn ProverPlanNode<B>>,
    limit: Limit,
}
pub struct VerifierLimitNode<B>
where
B:SnarkBackend
{
    input: Arc<dyn VerifierNode<B>>,
    limit: Limit,
}

use std::sync::Arc;

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion_expr::Distinct;

use crate::nodes::{prover::ProverPlanNode, verifier::VerifierNode};

pub struct ProverDistinctNode<B>
where
B:SnarkBackend
{
    input: Arc<dyn ProverPlanNode<B>>,
    distinct: Distinct,
}

pub struct VerifierDistinctNode<B>
where
B:SnarkBackend
{
    input: Arc<dyn VerifierNode<B>>,
    distinct: Distinct,
}

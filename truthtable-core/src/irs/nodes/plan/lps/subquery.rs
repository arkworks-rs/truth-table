use crate::nodes::{prover::ProverPlanNode, verifier::VerifierNode};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion_expr::Subquery;

use std::sync::Arc;
pub struct ProverSubqueryNode<B>
where
B:SnarkBackend
{
    input: Arc<dyn ProverPlanNode<B>>,
    subquery: Subquery,
}

pub struct VerifierSubqueryNode<B>
where
B:SnarkBackend
{
    input: Arc<dyn VerifierNode<B>>,
    subquery: Subquery,
}

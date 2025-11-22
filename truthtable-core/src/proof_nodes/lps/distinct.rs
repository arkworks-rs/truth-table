use std::sync::Arc;

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion_expr::Distinct;

use crate::proof_nodes::{prover::ProverPlanNode, verifier::VerifierNode};

pub struct ProverDistinctNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    input: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    distinct: Distinct,
}

pub struct VerifierDistinctNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    input: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    distinct: Distinct,
}

use crate::proof_nodes::{prover::ProverPlanNode, verifier::VerifierNode};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion_expr::Subquery;

use std::sync::Arc;
pub struct ProverSubqueryNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    input: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    subquery: Subquery,
}

pub struct VerifierSubqueryNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    input: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    subquery: Subquery,
}

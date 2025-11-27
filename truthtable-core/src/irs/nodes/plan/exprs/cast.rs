use std::sync::Arc;

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion_expr::Cast;

use crate::nodes::{prover::ProverPlanNode, verifier::VerifierNode};
#[derive(Clone)]
pub struct ProverCastExprNode<B>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    cast: Cast,
    input: Arc<dyn ProverPlanNode<B>>,
}
#[derive(Clone)]
pub struct VerifierCastExprNode<B>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    cast: Cast,
    input: Arc<dyn VerifierNode<B>>,
}

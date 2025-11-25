use crate::nodes::{prover::ProverPlanNode, verifier::VerifierNode};
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
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    input: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    subquery: Subquery,
}

pub struct VerifierSubqueryNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    input: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    subquery: Subquery,
}

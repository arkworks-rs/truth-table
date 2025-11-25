use std::sync::Arc;

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion_expr::Join;

use crate::nodes::{prover::ProverPlanNode, verifier::VerifierNode};

#[allow(clippy::type_complexity)]
pub struct ProverJoinNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    left: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    right: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    on: Vec<(
        Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
        Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    )>,
    filter: Option<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>>,
    join: Join,
}

#[allow(clippy::type_complexity)]
pub struct VerifierJoinNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    left: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    right: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    on: Vec<(
        Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
        Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    )>,
    filter: Option<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    join: Join,
}

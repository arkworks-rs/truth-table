use std::sync::Arc;

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion_expr::Join;

use crate::proof_nodes::{prover::ProverPlanNode, verifier::VerifierNode};

#[allow(clippy::type_complexity)]
pub struct ProverJoinNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
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
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
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

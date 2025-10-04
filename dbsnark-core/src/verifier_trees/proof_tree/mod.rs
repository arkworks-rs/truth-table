use std::sync::Arc;

use arithmetic::ctx::ProverCtx;
use ark_ff::PrimeField;
use ark_piop::{arithmetic::mat_poly::{lde::LDE, mle::MLE}, pcs::PCS};

use crate::verifier_trees::proof_tree::nodes::VerifierNode;

mod nodes;

#[derive(Clone)]
pub struct VerifierProofTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    ctx: ProverCtx<F, MvPCS, UvPCS>,
    root: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
}
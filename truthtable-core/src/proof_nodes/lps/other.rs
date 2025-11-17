use crate::proof_nodes::{
    HintGenerationPlan,
    cost::ProvingCost,
    prover::{ProverGadgetNode, ProverLpNode, ProverPlanNode},
    verifier::{VerifierLpNode, VerifierNode},
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
};
use datafusion::prelude::DataFrame;
use datafusion::prelude::SessionContext;
use datafusion_expr::LogicalPlan;
use indexmap::IndexMap;
use std::sync::Arc;

pub struct ProverOtherNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub inputs: Vec<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>>,
    pub kind: String,
}

pub struct VerifierOtherNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub inputs: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    pub kind: String,
}

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
use datafusion::{logical_expr::LogicalPlan, prelude::SessionContext};
use indexmap::IndexMap;
use std::sync::Arc;

pub struct ProverExtensionNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub inputs: Vec<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>>,
}

pub struct VerifierExtensionNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub inputs: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
}

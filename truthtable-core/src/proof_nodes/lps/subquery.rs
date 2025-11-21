use crate::proof_nodes::{
    HintDF,
    cost::ProvingCost,
    prover::{ArgProverGadget, ProverLpNode, ProverPlanNode},
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
pub struct ProverSubqueryNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub input: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
}

pub struct VerifierSubqueryNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub input: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
}

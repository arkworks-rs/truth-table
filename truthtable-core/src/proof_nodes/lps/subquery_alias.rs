use crate::proof_nodes::{
    HintGenerationPlan, OUTPUT_PLAN_KEY,
    cost::ProvingCost,
    prover::{ProverGadgetNode, ProverLpNode, ProverPlanNode},
    tree::NodeId,
    verifier::{VerifierLpNode, VerifierNode},
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::prelude::DataFrame;
use datafusion::prelude::SessionContext;
use datafusion_expr::LogicalPlan;
use indexmap::IndexMap;
use std::sync::Arc;

pub struct ProverSubqueryAliasNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub input_proof_tree_root: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
}
pub struct VerifierSubqueryAliasNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub input_proof_tree_root: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
}

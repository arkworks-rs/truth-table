use crate::proof_nodes::HintGenerationPlan;
use crate::proof_nodes::{
    cost::ProvingCost,
    id::NodeId,
    prover::{ArgProverExprNode, ProverGadgetNode, ProverPlanNode},
    verifier::{VerifierExprNode, VerifierNode},
};
use arithmetic::ctx::SharedCtx;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
};
use datafusion::prelude::DataFrame;
use datafusion::{logical_expr::Expr, prelude::SessionContext};
use std::sync::Arc;
#[derive(Clone)]
pub struct ProverScalarVariableExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub relative_expr: Expr,
    pub output_expr: Expr,
    pub inputs: Vec<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>>,
    pub parent_node_id: NodeId,
}

#[derive(Clone)]
pub struct VerifierScalarVariableExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub relative_expr: Expr,
    pub output_expr: Expr,
    pub inputs: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    pub parent_node_id: NodeId,
}

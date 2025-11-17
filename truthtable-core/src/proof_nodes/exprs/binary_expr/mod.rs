use crate::proof_nodes::HintGenerationPlan;

use crate::proof_nodes::tree::NodeId;
use crate::proof_nodes::{
    OUTPUT_PLAN_KEY,
    cost::ProvingCost,
    prover::{ProverExprNode, ProverGadgetNode, ProverPlanNode},
    verifier::{VerifierExprNode, VerifierNode},
};

use arithmetic::{
    ACTIVATOR_COL_NAME, col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::Prover,
    verifier::structs::oracle::TrackedOracle,
};
use datafusion::prelude::DataFrame;
use datafusion::{
    arrow::datatypes::{DataType, Field},
    logical_expr::{Expr, LogicalPlan, LogicalPlanBuilder, Operator},
};

use indexmap::IndexMap;
use ra_toolbox::expr_piop::binary_expr::{
    BinaryExprPIOP, BinaryExprPIOPProverInput, BinaryExprPIOPVerifierInput,
};
use std::sync::Arc;
#[derive(Clone)]
pub struct ProverBinaryExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub node_id: NodeId,
    pub left_prover_node: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    pub right_prover_node: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    pub parent_node_id: NodeId,
}
#[derive(Clone)]
pub struct VerifierBinaryExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub node_id: NodeId,
    pub left_verifier_node: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub right_verifier_node: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub parent_node_id: NodeId,
}

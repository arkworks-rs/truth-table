// Combined truthtable-core/src/prover/nodes/exprs/aggregate_function.rs and
// truthtable-core/src/verifier/nodes/exprs/aggregate_function.rs
use crate::proof_nodes::HintDF;
use crate::proof_nodes::OUTPUT_PLAN_KEY;
use crate::proof_nodes::tree::NodeId;
use arithmetic::{
    ACTIVATOR_COL_NAME, col::TrackedCol, col_oracle::TrackedColOracle, ctx::SharedCtx,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::Prover,
};
use datafusion::prelude::DataFrame;
use datafusion::{
    arrow::datatypes::SchemaRef, common::Statistics, logical_expr::Expr, prelude::SessionContext,
};

use ra_toolbox::expr_piop::aggregate_function::{
    AggregateFunctionExprPIOP, AggregateFunctionPIOPProverInput, AggregateFunctionPIOPVerifierInput,
};
use std::sync::Arc;

use crate::proof_nodes::{
    cost::ProvingCost,
    prover::{ArgProverExprNode, ProverGadget, ProverPlanNode},
    verifier::{VerifierExprNode, VerifierNode},
};
#[derive(Clone)]
pub struct ProverAggregateFunctionExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub node_id: NodeId,
    pub inputs: Vec<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>>,
    pub parent_node_id: NodeId,
}
#[derive(Clone)]
pub struct VerifierAggregateFunctionExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub node_id: NodeId,
    pub inputs: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    pub parent_node_id: NodeId,
}

use crate::proof_nodes::{
    HintDF, OUTPUT_PLAN_KEY,
    cost::ProvingCost,
    prover::ProverPlanNode,
    tree::NodeId,
    verifier::{VerifierExprNode, VerifierNode},
};
use arithmetic::{
    ACTIVATOR_COL_NAME, ctx::SharedCtx, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::prelude::DataFrame;
use datafusion::{
    arrow::datatypes::{Field, FieldRef, Schema, SchemaRef},
    common::Statistics,
    logical_expr::Expr,
    prelude::SessionContext,
};

use indexmap::IndexMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct ProverAliasExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub node_id: NodeId,
    pub input: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    pub parent_node_id: NodeId,
}
#[derive(Clone)]
pub struct VerifierAliasExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub node_id: NodeId,
    pub input: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub parent_node_id: NodeId,
}

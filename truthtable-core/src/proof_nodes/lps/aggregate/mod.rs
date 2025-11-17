mod hints;
use crate::proof_nodes::{
    HintGenerationPlan, OUTPUT_PLAN_KEY,
    cost::ProvingCost,
    prover::{ProverGadgetNode, ProverLpNode, ProverPlanNode},
    tree::NodeId,
    verifier::{VerifierLpNode, VerifierNode},
};
use arithmetic::{
    ACTIVATOR_COL_NAME, ctx::SharedCtx, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::{Prover, structs::polynomial::TrackedPoly},
    verifier::structs::oracle::TrackedOracle,
};
use datafusion::prelude::DataFrame;
use datafusion::{
    arrow::datatypes::{DataType, Field, FieldRef, Schema, SchemaRef},
    common::Statistics,
    logical_expr::LogicalPlan,
    prelude::{Expr, SessionContext},
};

use indexmap::IndexMap;
use ra_toolbox::lp_piop::aggregate_check::{
    AggregatePIOP, AggregatePIOPProverInput, AggregatePIOPProverOutput, AggregatePIOPVerifierInput,
    AggregatePIOPVerifierOutput,
};
use std::sync::Arc;

pub struct ProverAggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub group_expr_proof_tree_roots: Vec<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>>,
    pub aggr_expr_proof_tree_roots: Vec<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>>,
    pub input_proof_tree_root: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
}

pub struct VerifierAggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub group_expr_proof_tree_roots: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    pub aggr_expr_proof_tree_roots: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    pub input_proof_tree_root: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
}

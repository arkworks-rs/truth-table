use crate::proof_nodes::{
    HintGenerationPlan, OUTPUT_PLAN_KEY, cost::ProvingCost, prover::{ProverGadgetNode, ProverLpNode, ProverPlanNode}, tree::NodeId, verifier::{VerifierLpNode, VerifierNode}
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
    prover::Prover,
};
use datafusion::prelude::DataFrame;
use datafusion::{
    arrow::datatypes::{DataType, Field, FieldRef, Schema},
    logical_expr::{self as df, ExprSchemable, LogicalPlan, LogicalPlanBuilder},
    prelude::{Expr, SessionContext},
};

use indexmap::IndexMap;
use ra_toolbox::lp_piop::filter_check::{
    FilterPIOP, FilterPIOPProverInput, FilterPIOPVerifierInput,
};
use std::sync::Arc;

/// The implementation of a filter node in the prover proof tree.
pub struct ProverFilterNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// Child proof plan for the filter predicate expression.
    pub predicate_prover_node: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    /// Child proof plan for the input logical plan to be filtered.
    pub input_prover_node: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    /// The unique identifier for this node.
    pub node_id: NodeId,
    /// The DataFusion expression representing the predicate; cached so we can
    /// rebuild logical plans without relying on node ids.
    pub predicate_expr: Expr,
}

/// The implementation of a filter node in the verification proof tree.
pub struct VerifierFilterNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// Child proof plan for the filter predicate expression.
    pub predicate_verifier_node: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    /// Child proof plan for the input logical plan to be filtered.
    pub input_verifier_node: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    /// The unique identifier for this node.
    pub node_id: NodeId,
    /// Cached predicate expression (see prover counterpart comment).
    pub predicate_expr: Expr,
}

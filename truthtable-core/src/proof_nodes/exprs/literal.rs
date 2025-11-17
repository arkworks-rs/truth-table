use crate::proof_nodes::{
    HintGenerationPlan, OUTPUT_PLAN_KEY, cost::ProvingCost, prover::{ArgProverExprNode, ProverGadgetNode, ProverPlanNode}, tree::NodeId, verifier::{VerifierExprNode, VerifierNode}
};
use arithmetic::{
    ctx::SharedCtx, encoding::encode_arrow_array_to_field, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    prover::Prover,
    verifier::Verifier,
};
use datafusion::prelude::DataFrame;
use datafusion::{
    arrow::datatypes::{Field, Schema, SchemaRef},
    common::Statistics,
    logical_expr::{Expr, LogicalPlan, LogicalPlanBuilder},
    prelude::SessionContext,
};

use std::sync::Arc;
#[derive(Clone)]
pub struct ProverLiteralExprNode {
    pub node_id: NodeId,
    pub parent_node_id: NodeId,
}

#[derive(Clone)]
pub struct VerifierLiteralExprNode {
    pub node_id: NodeId,
    pub parent_node_id: NodeId,
}

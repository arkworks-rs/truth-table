// Combined truthtable-core/src/prover/nodes/exprs/cast.rs and
// truthtable-core/src/verifier/nodes/exprs/cast.rs
use crate::proof_nodes::HintDF;
use crate::proof_nodes::tree::NodeId;
use crate::proof_nodes::{
    OUTPUT_PLAN_KEY,
    cost::ProvingCost,
    prover::{ArgProverExprNode, ProverGadget, ProverPlanNode},
    verifier::{VerifierExprNode, VerifierNode},
};
use arithmetic::{
    ACTIVATOR_COL_NAME, ctx::SharedCtx, encoding::encode_arrow_array_to_field, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::prelude::DataFrame;
use datafusion::{
    arrow::datatypes::{Field, Schema},
    logical_expr::Expr,
    prelude::SessionContext,
};

use indexmap::IndexMap;
use std::sync::Arc;
#[derive(Clone)]
pub struct ProverCastExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub node_id: NodeId,
    pub parent_node_id: NodeId,
    pub input: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
}
#[derive(Clone)]
pub struct VerifierCastExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub node_id: NodeId,
    pub parent_node_id: NodeId,
    pub input: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
}

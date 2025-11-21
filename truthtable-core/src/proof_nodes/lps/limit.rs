use crate::proof_nodes::{
    HintDF, OUTPUT_PLAN_KEY,
    cost::ProvingCost,
    prover::{ArgProverGadget, ProverLpNode, ProverPlanNode},
    tree::NodeId,
    verifier::{VerifierLpNode, VerifierNode},
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
};
use datafusion::prelude::DataFrame;
use datafusion::{
    logical_expr::{self as df, LogicalPlan, LogicalPlanBuilder},
    prelude::SessionContext,
};

use datafusion_expr::{
    Limit, SortExpr,
    logical_plan::{FetchType, SkipType},
};
use indexmap::IndexMap;
use std::sync::Arc;

pub struct ProverLimitNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub input: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
    pub limit: Limit,
}
pub struct VerifierLimitNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub input: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
    pub limit: Limit,
}

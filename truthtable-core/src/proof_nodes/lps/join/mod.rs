mod hints;

use crate::proof_nodes::{
    HintGenerationPlan, OUTPUT_PLAN_KEY,
    cost::ProvingCost,
    lps::join::hints::{
        JOIN_ALL_KEY_SUPP, JOIN_LEFT_KEY_SOURCE, JOIN_LEFT_KEY_SUPP, JOIN_OUTPUT_KEY_SUPP,
        JOIN_RIGHT_KEY_SOURCE, JOIN_RIGHT_KEY_SUPP, build_join_hint_generation_plans,
    },
    prover::{ProverGadgetNode, ProverLpNode, ProverPlanNode},
    tree::NodeId,
    verifier::{VerifierLpNode, VerifierNode},
};
use arithmetic::{
    ACTIVATOR_COL_NAME,
    table::{ArithTable, TrackedTable},
    table_oracle::TrackedTableOracle,
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
    arrow::datatypes::{FieldRef, Schema},
    logical_expr::Join,
    prelude::SessionContext,
};

use datafusion_expr::{Expr, LogicalPlan};
use indexmap::IndexMap;
use ra_toolbox::lp_piop::join_check::{
    InnerJoinPIOP, InnerJoinProverInput, InnerJoinVerifierInput,
};
use std::{collections::HashSet, sync::Arc};

#[allow(clippy::type_complexity)]
pub struct ProverJoinNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub left_proof_tree_root: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    pub right_proof_tree_root: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    pub on_proof_tree_roots: Vec<(
        Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
        Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    )>,
    pub filter_proof_tree_root: Option<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>>,
    pub node_id: NodeId,
}

#[allow(clippy::type_complexity)]
pub struct VerifierJoinNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub left_proof_tree_root: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub right_proof_tree_root: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub on_proof_tree_roots: Vec<(
        Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
        Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    )>,
    pub filter_proof_tree_root: Option<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    pub node_id: NodeId,
}

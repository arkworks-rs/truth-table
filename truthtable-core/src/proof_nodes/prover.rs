//! The proof plan module contains a set of tools to build a proof plan from a
//! DataFusion logical plan.

use super::cost::ProvingCost;
use crate::{
    proof_nodes::HintDF,
    prover::trees::{gadget_tree::GadgetTree, proof_tree::ProverProofTree},
    tree::NodeId,
};
use arithmetic::ctx::SharedCtx;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
};
use datafusion::{
    arrow::datatypes::SchemaRef,
    common::Statistics,
    logical_expr::LogicalPlan,
    prelude::{DataFrame, Expr, SessionContext},
};
use indexmap::IndexMap;
use std::{any::Any, sync::Arc};
use tracing::trace;

pub use super::{cost, exprs, lps};

pub trait ProverGadget<F, MvPCS, UvPCS>: Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn hints(&self, input: &IndexMap<String, HintDF>) -> IndexMap<String, HintDF>;
    fn children(&self) -> Vec<Arc<dyn ProverGadget<F, MvPCS, UvPCS>>>;
    fn name(&self) -> String;
    fn display(&self) -> String {
        self.name()
    }
    fn child_edge_labels(&self) -> Vec<Option<String>> {
        self.children().into_iter().map(|_| None).collect()
    }
}

/// Common interface for a proof plan node.
///
/// A proof plan is a tree of nodes, where each node represents a proof unit.
pub trait ProverPlanNode<F, MvPCS, UvPCS>: Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn name(&self) -> String {
        self.node_id().to_string()
    }

    fn display(&self) -> String {
        self.name()
    }

    fn gadget_tree(&self) -> GadgetTree<F, MvPCS, UvPCS>;

    fn node_id(&self) -> NodeId;

    fn child_edge_labels(&self) -> Vec<Option<String>> {
        self.children().into_iter().map(|_| None).collect()
    }
    fn children(&self) -> Vec<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>>;
    fn output(&self, _proof_tree: &ProverProofTree<F, MvPCS, UvPCS>) -> HintDF;
    fn ctx_lp_node(
        &self,
        proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>;

    fn arithmetic_post_process(&self);

    /// Complete the piop plan
    fn add_virtual_witness(&self, prover: &mut ark_piop::prover::ArgProver<F, MvPCS, UvPCS>);

    fn add_virtual_witness_recursive(
        &self,
        prover: &mut ark_piop::prover::ArgProver<F, MvPCS, UvPCS>,
    ) {
        trace!(
            "Prover finished add_virtual_witness_recursive: {}",
            self.name()
        );
    }

    fn prove_piop_recursive(
        &self,
        prover: &mut ark_piop::prover::ArgProver<F, MvPCS, UvPCS>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn cost(&self, statistics: Statistics, schema: SchemaRef) -> ProvingCost;
}

pub trait ProverLpNode<F, MvPCS, UvPCS>:
    ProverPlanNode<F, MvPCS, UvPCS> + Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    /// Constructs a proof plan node from a DataFusion logical plan.
    // TODO: We might not need ctx here
    fn from_lp(
        _ctx: &SessionContext,
        _prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        _plan: LogicalPlan,
        _parent: NodeId,
    ) -> Self
    where
        Self: Sized;
}

pub trait ProverExprNode<F, MvPCS, UvPCS>:
    ProverPlanNode<F, MvPCS, UvPCS> + Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    /// Constructs a proof plan node from a DataFusion expression and its parent
    /// logical plan.
    // TODO: We might not need ctx and parent_logical_plan here
    fn from_expr(
        _ctx: &SessionContext,
        _prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        _expr: Expr,
        _parent: NodeId,
    ) -> Self
    where
        Self: Sized;
}

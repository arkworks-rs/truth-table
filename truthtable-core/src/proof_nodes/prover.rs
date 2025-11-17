//! The proof plan module contains a set of tools to build a proof plan from a
//! DataFusion logical plan.

use super::cost::ProvingCost;
use crate::{
    proof_nodes::HintGenerationPlan,
    prover::trees::proof_tree::ProverProofTree,
    tree::{Node, NodeId},
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
    prelude::{Expr, SessionContext},
};
use std::{any::Any, sync::Arc};
use tracing::trace;

pub use super::{cost, display, exprs, lps};

pub trait ProverGadgetNode<F, MvPCS, UvPCS>: Node<F, MvPCS, UvPCS> + Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    /// A map of named logical plans that can be used to materialize witnesses
    /// for this node. Logical plan nodes typically return a single entry with
    /// the key `OUTPUT_PLAN_KEY`.
    ///
    /// Note that if your column can be generated from other columns, It doesn't
    /// need to be materialized and should be added to the 'add_virtual_witness'
    /// function.
    fn hint_generation_plans(
        &self,
        _proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> indexmap::IndexMap<String, HintGenerationPlan>;

    fn arithmetic_post_process(&self);

    /// Complete the piop plan
    fn add_virtual_witness(&self, prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>);

    fn add_virtual_witness_recursive(
        &self,
        prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
        trace!(
            "Prover finished add_virtual_witness_recursive: {}",
            self.name()
        );
    }

    fn prove_piop(
        &self,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()>;

    fn prove_piop_recursive(
        &self,
        prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn cost(&self, statistics: Statistics, schema: SchemaRef) -> ProvingCost;
}

/// Common interface for a proof plan node.
///
/// A proof plan is a tree of nodes, where each node represents a proof unit.
pub trait ProverPlanNode<F, MvPCS, UvPCS>:
    ProverGadgetNode<F, MvPCS, UvPCS> + Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn output(&self, _proof_tree: &ProverProofTree<F, MvPCS, UvPCS>) -> HintGenerationPlan;
    fn ctx_lp_node(
        &self,
        proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>;
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
        _parent_node_id: NodeId,
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
        _parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized;
}

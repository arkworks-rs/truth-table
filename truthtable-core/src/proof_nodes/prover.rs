//! The proof plan module contains a set of tools to build a proof plan from a
//! DataFusion logical plan.

use super::cost::ProvingCost;
use crate::{
    proof_nodes::{HintGenerationPlan, id::NodeId},
    prover::trees::{
        arithmetized_tree::ProverArithmetizedTree, piop_tree::ProverPIOPTree,
        proof_tree::ProverProofTree,
    },
};
use arithmetic::ctx::SharedCtx;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    prover::Prover,
};
use datafusion::{
    arrow::datatypes::SchemaRef,
    common::Statistics,
    logical_expr::LogicalPlan,
    prelude::{Expr, SessionContext},
};
use indexmap::IndexMap;
use std::{any::Any, sync::Arc};
use tracing::trace;

pub use super::{cost, display, exprs, lps};

/// Common interface for a proof plan node.
///
/// A proof plan is a tree of nodes, where each node represents a proof unit.
pub trait ProverNode<F, MvPCS, UvPCS>: Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    /// Short name for the ProverNode node, such as `FilterNode`.
    /// Children of this node expressed as proof plan trait objects. Leaf nodes
    /// return an empty list.
    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>>;

    /// Appends all the descendants of this node in 'post-order' to the given
    /// mutable vector.
    /// Post-order over descendants: for each child, traverse its descendants
    /// first, then push the child; the current node itself is not included.
    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
    }

    /// Optional human-readable labels for each child edge.
    /// Default implementation leaves every edge unlabeled.
    fn child_edge_labels(&self) -> Vec<Option<String>> {
        self.children().into_iter().map(|_| None).collect()
    }

    /// A human-readable name for this node
    fn name(&self) -> String {
        self.node_id().to_string()
    }

    /// Classification of this node (used for optional metadata extraction).
    fn node_id(&self) -> NodeId;

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
    ) -> IndexMap<String, HintGenerationPlan> {
        IndexMap::new()
    }
    fn arithmetic_post_process(
        &self,
        arithmetized_tree: &mut ProverArithmetizedTree<F, MvPCS, UvPCS>,
    ) {
        let _ = arithmetized_tree;
    }

    /// Complete the piop plan
    fn add_virtual_witness(
        &self,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
        prover: &mut Prover<F, MvPCS, UvPCS>,
    ) {
        let _ = (piop_tree, prover);
    }

    fn add_virtual_witness_recursive(
        &self,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
        prover: &mut Prover<F, MvPCS, UvPCS>,
    ) {
        for child in self.children() {
            child.add_virtual_witness_recursive(piop_tree, prover);
        }
        self.add_virtual_witness(piop_tree, prover);
        trace!(
            "Prover finished add_virtual_witness_recursive: {}",
            self.name()
        );
    }

    fn prove_piop(
        &self,
        _prover: &mut Prover<F, MvPCS, UvPCS>,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let _ = piop_tree;
        Ok(())
    }

    fn prove_piop_recursive(
        &self,
        prover: &mut Prover<F, MvPCS, UvPCS>,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        self.prove_piop(prover, piop_tree)?;
        for child in self.children() {
            child.prove_piop_recursive(prover, piop_tree)?;
        }
        Ok(())
    }

    fn cost(&self, statistics: Statistics, schema: SchemaRef) -> ProvingCost;
    fn ctx_lp_node(
        &self,
        proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverNode<F, MvPCS, UvPCS>>;
}

impl<F, MvPCS, UvPCS> dyn ProverNode<F, MvPCS, UvPCS> + '_
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    /// Returns the Proof plan as `Any` so that it can be downcast to a specific
    /// implementation.
    pub fn as_any(&self) -> &dyn Any {
        self
    }
}

pub trait ProverLpNode<F, MvPCS, UvPCS>: ProverNode<F, MvPCS, UvPCS> + Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
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

pub trait ProverExprNode<F, MvPCS, UvPCS>: ProverNode<F, MvPCS, UvPCS> + Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
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

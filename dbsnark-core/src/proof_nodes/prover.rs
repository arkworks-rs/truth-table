//! The proof plan module contains a set of tools to build a proof plan from a
//! DataFusion logical plan.

use crate::proof_nodes::id::NodeId;
use crate::{

    prover::trees::piop_tree::ProverPIOPTree,
};
use super::cost::ProvingCost;
use std::{any::Any, sync::Arc};
use indexmap::IndexMap;
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
    /// Constructs a proof plan node from a DataFusion expression and its parent
    /// logical plan.
    // TODO: We might not need ctx and parent_logical_plan here
    fn from_expr(
        ctx: &SessionContext,
        _prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        parent_logical_plan: LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        unimplemented!()
    }
    /// Constructs a proof plan node from a DataFusion logical plan.
    // TODO: We might not need ctx here
    fn from_lp(
        ctx: &SessionContext,
        _prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        unimplemented!()
    }

    /// Returns the Proof plan as `Any` so that it can be downcast to a specific
    /// implementation.
    fn as_any(&self) -> &dyn Any;

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

    /// A human-readable name for this node
    fn name(&self) -> String {
        self.node_id().to_string()
    }

    /// Classification of this node (used for optional metadata extraction).
    fn node_id(&self) -> NodeId;

    /// A map of named logical plans that can be used to materialize witnesses
    /// for this node. Logical plan nodes typically return a single entry with
    /// the key `"output_plan"`.
    ///
    /// Note that if your column can be generated from other columns, It doesn't
    /// need to be materialized and should be added to the 'add_virtual_witness'
    /// function.
    fn hint_generation_plans(&self) -> IndexMap<String, LogicalPlan> {
        IndexMap::new()
    }

    /// Complete the piop plan
    fn add_virtual_witness(
        &self,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
        prover: &mut Prover<F, MvPCS, UvPCS>,
    );

    fn prove_piop(
        &self,
        _prover: &mut Prover<F, MvPCS, UvPCS>,
        _piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        todo!()
    }

    fn cost(&self, statistics: Statistics, schema: SchemaRef) -> ProvingCost;
}

pub fn output_prover_logical_plan<F, MvPCS, UvPCS>(
    node: &Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
) -> Option<LogicalPlan>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    node.hint_generation_plans()
        .into_iter()
        .find_map(|(label, plan)| {
            if label == "output_plan" {
                Some(plan)
            } else {
                None
            }
        })
}

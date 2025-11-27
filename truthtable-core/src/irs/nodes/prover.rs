//! The proof plan module contains a set of tools to build a proof plan from a
//! DataFusion logical plan.

use arithmetic::ctx::SharedCtx;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
};
use datafusion::{
    logical_expr::LogicalPlan,
    prelude::{Expr, SessionContext},
};
use std::{any::Any, sync::Arc};

use crate::irs::{nodes::id::NodeId, tree::Node};

pub trait Gadget<B>: Node<B> + Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    /// Returns the children gadgets of this gadget. Note that the child of a gadget is a gadget, not a plan node.
    fn children(&self) -> Vec<Arc<Self>>
    where
        Self: Sized;
    /// Optional human-readable labels for each child edge.
    fn child_edge_labels(&self) -> Vec<Option<String>>
    where
        Self: Sized,
    {
        self.children().into_iter().map(|_| None).collect()
    }
    /// Runs the gadget prover
    fn prove() -> SnarkResult<()>
    where
        Self: Sized;
}

pub trait PlanNode<B>: Node<B> + Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    /// Returns the children plan nodes of this plan node. Note that the child of a plan node is a plan node, not a gadget.
    fn children(&self) -> Vec<Arc<Self>>
    where
        Self: Sized;
    /// Optional human-readable labels for each child edge.
    fn child_edge_labels(&self) -> Vec<Option<String>>
    where
        Self: Sized,
    {
        self.children().into_iter().map(|_| None).collect()
    }
    /// Returns the gadget associated with this plan node. Note that each plan node has exactly one gadget.
    fn gadget(&self) -> Arc<dyn Gadget<B>>;
}

pub trait LpNode<B>: PlanNode<B> + Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    /// Constructs a proof plan node from a DataFusion logical plan.
    // TODO: We might not need ctx here
    fn from_lp(
        _ctx: &SessionContext,
        _prover_ctx: SharedCtx<B>,
        _plan: LogicalPlan,
        _parent: NodeId,
    ) -> Self
    where
        Self: Sized;
}

pub trait ExprNode<B>: PlanNode<B> + Any + Send + Sync
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
        _prover_ctx: SharedCtx<B>,
        _expr: Expr,
        _parent: NodeId,
    ) -> Self
    where
        Self: Sized;
}

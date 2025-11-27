use super::nodes::{cost::ProvingCost, id::NodeId};
use crate::irs::nodes::hints::HintDF;
use arithmetic::ctx::SharedCtx;
use ark_piop::SnarkBackend;
use ark_piop::errors::SnarkResult;
use ark_std::fmt::Debug;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::{
    logical_expr::LogicalPlan,
    prelude::{Expr, SessionContext},
};
use datafusion_common::Statistics;
use indexmap::IndexMap;
use std::{any::Any, sync::Arc};

/// The abstraction of a tree structure used in intermediate representations
#[derive(Debug)]
pub struct Tree<B>
where
    B: SnarkBackend,
{
    root: Arc<dyn Node<B>>,
    arena: IndexMap<NodeId, Arc<dyn Node<B>>>,
}

impl<B> Clone for Tree<B>
where
    B: SnarkBackend,
{
    fn clone(&self) -> Self {
        Self {
            root: Arc::clone(&self.root),
            arena: self.arena.clone(),
        }
    }
}
impl<B> Tree<B>
where
    B: SnarkBackend,
{
    /// Get the root node of this tree.
    fn root(&self) -> Arc<dyn Node<B>> {
        Arc::clone(&self.root)
    }

    /// Get the arena of nodes in this tree.
    pub fn arena(&self) -> &IndexMap<NodeId, Arc<dyn Node<B>>> {
        &self.arena
    }

    /// Get a node by its ID from the arena.
    pub fn get_node(&self, node_id: &NodeId) -> Option<&Arc<dyn Node<B>>> {
        self.arena.get(node_id)
    }

    /// Display the tree in Graphviz DOT format.
    fn display_graphviz(&self, inner: bool) -> String {
        todo!()
    }
}

pub trait Payload: Debug + 'static {}

pub trait Node<B>: Any + Send + Sync + Debug
where
    B: SnarkBackend,
{
    /// Returns the unique identifier of this node.
    fn id(&self) -> NodeId;
    /// Returns the human-readable name of this node.
    fn name(&self) -> String {
        self.id().to_string()
    }
    /// Returns a human-readable representation of this node.
    fn display(&self) -> String {
        self.name()
    }
    /// Estimates the proving cost of this node given statistics and schema.
    fn cost(&self, statistics: Statistics, schema: SchemaRef) -> ProvingCost;
}

pub trait Gadget<B>: Node<B> + Any + Send + Sync
where
    B: SnarkBackend,
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
    B: SnarkBackend,
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
    B: SnarkBackend,
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
    B: SnarkBackend,
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

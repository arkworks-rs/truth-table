use crate::irs::nodes::{Node, NodeId};
use ark_piop::SnarkBackend;
use ark_std::fmt::Debug;
use datafusion::{logical_expr::LogicalPlan, prelude::Expr};
use derivative::Derivative;
use indexmap::IndexMap;
use std::sync::Arc;
fn build_arena<B>(root: &Node<B>) -> IndexMap<NodeId, Node<B>>
where
    B: SnarkBackend,
{
    todo!()
}

/// The abstraction of a tree structure used in intermediate representations
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Tree<B>
where
    B: SnarkBackend,
{
    root: Node<B>,
    arena: IndexMap<NodeId, Node<B>>,
}

impl<B> Tree<B>
where
    B: SnarkBackend,
{
    pub fn new(root: Node<B>, arena: IndexMap<NodeId, Node<B>>) -> Self {
        Self { root, arena }
    }

    /// Get the root node of this tree.
    pub fn root(&self) -> &Node<B> {
        &self.root
    }

    /// Get the arena of nodes in this tree.
    pub fn arena(&self) -> &IndexMap<NodeId, Node<B>> {
        &self.arena
    }

    /// Get a node by its ID from the arena.
    pub fn get_node(&self, node_id: &NodeId) -> Option<&Node<B>> {
        self.arena.get(node_id)
    }

    /// Display the tree in Graphviz DOT format.
    pub fn display_graphviz(&self, inner: bool) -> String {
        todo!()
    }

    pub fn from_logical_plan(lp: &LogicalPlan) -> Self {
        let root = Node::<B>::from_lp(lp.clone());
        let arena = build_arena(&root);
        Self { root, arena }
    }

    pub fn from_expr(expr: &Expr, parent: Option<&Node<B>>) -> Self {
        let root = Node::<B>::from_expr(expr, parent);
        let arena = build_arena(&root);
        Self { root, arena }
    }
}

pub trait Payload: Debug + 'static {}

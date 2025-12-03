use crate::irs::nodes::{IsNode, Node, NodeId};
use ark_piop::SnarkBackend;
use ark_std::fmt::Debug;
use datafusion::{logical_expr::LogicalPlan, prelude::Expr};
use derivative::Derivative;
use indexmap::IndexMap;
use std::collections::hash_map::DefaultHasher;
use std::fmt::Display;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Weak};

fn build_arena<B>(root: &Arc<Node<B>>) -> IndexMap<NodeId, Arc<Node<B>>>
where
    B: SnarkBackend,
{
    fn visit<B>(node: &Arc<Node<B>>, arena: &mut IndexMap<NodeId, Arc<Node<B>>>)
    where
        B: SnarkBackend,
    {
        let mut hasher = DefaultHasher::new();
        node.hash(&mut hasher);
        let id = hasher.finish();
        if arena.contains_key(&id) {
            return;
        }
        for child in node.children() {
            visit(&child, arena);
        }
        arena.insert(id, node.clone());
    }

    let mut arena = IndexMap::new();
    visit(root, &mut arena);
    arena
}

/// The abstraction of a tree structure used in intermediate representations
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Tree<B>
where
    B: SnarkBackend,
{
    root: Arc<Node<B>>,
    arena: IndexMap<NodeId, Arc<Node<B>>>,
}

impl<B> Tree<B>
where
    B: SnarkBackend,
{
    pub fn new(root: Arc<Node<B>>, arena: IndexMap<NodeId, Arc<Node<B>>>) -> Self {
        Self { root, arena }
    }

    pub fn new_from_root(root: Arc<Node<B>>) -> Self {
        let arena = build_arena(&root);
        Self { root, arena }
    }

    /// Get the root node of this tree.
    pub fn root(&self) -> &Arc<Node<B>> {
        &self.root
    }

    /// Get the arena of nodes in this tree.
    pub fn arena(&self) -> &IndexMap<NodeId, Arc<Node<B>>> {
        &self.arena
    }

    /// Get a node by its ID from the arena.
    pub fn get_node(&self, node_id: &NodeId) -> Option<&Arc<Node<B>>> {
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

    pub fn from_expr(expr: &Expr, parent: Option<Weak<Node<B>>>, scope: Arc<Node<B>>) -> Self {
        let root = Node::<B>::from_expr(expr, parent, scope);
        let arena = build_arena(&root);
        Self { root, arena }
    }
}

pub trait Payload: Display + Debug + 'static {}

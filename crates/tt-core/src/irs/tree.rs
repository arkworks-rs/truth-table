//! Arena-backed tree of IR nodes.
//!
//! A [`Tree`] is a root [`Node`] plus an `IndexMap<NodeId, Arc<Node>>` arena
//! covering every reachable descendant, so passes can look up nodes by id in
//! O(1) without re-walking the tree. Nodes are shared via `Arc` so that DAG
//! shapes (e.g. a sub-expression referenced from multiple parents) stay
//! single-owned rather than being duplicated.

use crate::irs::nodes::{IsNode, Node, NodeId};
use ark_piop::SnarkBackend;
use ark_std::fmt::Debug;
use datafusion::{logical_expr::LogicalPlan, prelude::Expr};
use derivative::Derivative;
use indexmap::IndexMap;
use std::fmt::Display;
use std::sync::{Arc, Weak};

fn build_arena<B>(root: &Arc<Node<B>>) -> IndexMap<NodeId, Arc<Node<B>>>
where
    B: SnarkBackend,
{
    fn visit<B>(node: &Arc<Node<B>>, arena: &mut IndexMap<NodeId, Arc<Node<B>>>)
    where
        B: SnarkBackend,
    {
        let id = node.id();
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

/// Root-plus-arena tree used by every IR stage.
///
/// Construct with [`Tree::new_from_root`] to build the arena automatically, or
/// with [`Tree::new`] when you already have a consistent arena (e.g. from a
/// pass that clones the parent IR). [`Tree::from_logical_plan`] is the
/// starting point for prover / verifier pipelines.
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
    /// Construct a tree from an existing root and a consistent arena.
    ///
    /// The caller must ensure every node reachable from `root` appears in
    /// `arena`. Prefer [`Tree::new_from_root`] when in doubt.
    pub fn new(root: Arc<Node<B>>, arena: IndexMap<NodeId, Arc<Node<B>>>) -> Self {
        Self { root, arena }
    }

    /// Construct a tree by walking `root` and building the arena automatically.
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
    pub fn display_graphviz(&self, _inner: bool) -> String {
        todo!()
    }

    /// Build a [`Tree`] from a DataFusion [`LogicalPlan`] by lowering each
    /// plan node and expression into the corresponding IR node.
    pub fn from_logical_plan(lp: &LogicalPlan) -> Self {
        let root = Node::<B>::from_lp(lp.clone());
        let arena = build_arena(&root);
        Self { root, arena }
    }

    /// Build a [`Tree`] rooted at a single [`Expr`], carrying its `parent`
    /// weak-ref and `scope` for later symbol resolution.
    pub fn from_expr(
        expr: &Expr,
        parent: Option<Weak<Node<B>>>,
        scope: Vec<Weak<Node<B>>>,
    ) -> Self {
        let root = Node::<B>::from_expr(expr, parent, scope);
        let arena = build_arena(&root);
        Self { root, arena }
    }
}

/// Marker trait every IR payload must implement.
///
/// The `Display` bound is used by `Ir::display_graphviz` to render a payload
/// below its node in DOT output; `Debug` is used for tracing; `'static` lets
/// passes store payloads in heterogeneous containers without lifetime gymnastics.
pub trait Payload: Display + Debug + 'static {}

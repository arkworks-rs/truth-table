//! Arena-backed tree of IR nodes.
//!
//! A [`Tree`] is a root [`Node`] plus an arena of every reachable descendant,
//! so a pass looks a node up by id without walking the tree. Nodes are shared
//! via `Arc`, so a node referenced from several parents is stored once.

use crate::irs::nodes::{IsNode, Node, NodeId};
use ark_piop::SnarkBackend;
use ark_std::fmt::Debug;
use datafusion::{logical_expr::LogicalPlan, prelude::Expr};
use derivative::Derivative;
use indexmap::IndexMap;
use std::collections::BTreeSet;
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
    /// Every node reachable from `root` must appear in `arena`.
    pub fn new(root: Arc<Node<B>>, arena: IndexMap<NodeId, Arc<Node<B>>>) -> Self {
        Self { root, arena }
    }

    pub fn new_from_root(root: Arc<Node<B>>) -> Self {
        let arena = build_arena(&root);
        Self { root, arena }
    }

    pub fn root(&self) -> &Arc<Node<B>> {
        &self.root
    }

    pub fn arena(&self) -> &IndexMap<NodeId, Arc<Node<B>>> {
        &self.arena
    }

    /// The name of the node that has `id` among its children.
    pub fn parent_name(&self, id: NodeId) -> Option<String> {
        self.arena
            .values()
            .find(|node| node.children().iter().any(|child| child.id() == id))
            .map(|node| node.name())
    }

    pub fn get_node(&self, node_id: &NodeId) -> Option<&Arc<Node<B>>> {
        self.arena.get(node_id)
    }

    /// The string columns some white-box string gadget (e.g. `Like`) reads
    /// char-level side polys for. Arithmetization (prover) and tracking
    /// (verifier) carry side polys only for these; every other string column
    /// has its hash and length encoding only (paper: "Dropping Auxiliary
    /// Columns"). Both sides derive the set from the same tree.
    pub fn required_side_columns(&self) -> BTreeSet<String> {
        let mut cols = BTreeSet::new();
        for node in self.arena.values() {
            cols.extend(node.required_side_columns());
        }
        cols
    }

    /// The fingerprint limbs, per string column, that some pre-filter tests.
    /// Table scans carry exactly these `__fp{j}` columns on both sides.
    pub fn required_fingerprint_columns(&self) -> arithmetic::encoding::FingerprintSelection {
        let mut selection = arithmetic::encoding::FingerprintSelection::new();
        for node in self.arena.values() {
            for (column, limbs) in node.required_fingerprint_columns() {
                selection.entry(column).or_default().extend(limbs);
            }
        }
        selection
    }

    /// The `(table, column)` string columns some sort reads the rank of
    /// (TruthTable++ §3.2). Every scan of such a table carries that column's
    /// `__rank` segment, on both sides, and the table must commit it.
    pub fn required_rank_columns(&self) -> BTreeSet<(String, String)> {
        let mut cols = BTreeSet::new();
        for node in self.arena.values() {
            cols.extend(node.required_rank_columns());
        }
        #[cfg(feature = "test-utils")]
        cols.extend(crate::test_utils::forced_ranks::forced_rank_columns());
        cols
    }

    pub fn display_graphviz(&self, _inner: bool) -> String {
        todo!()
    }

    pub fn from_logical_plan(lp: &LogicalPlan) -> Self {
        let root = Node::<B>::from_lp(lp.clone());
        let arena = build_arena(&root);
        Self { root, arena }
    }

    /// `parent` and `scope` are kept on the root for symbol resolution.
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

/// Marker trait of IR payloads. `Ir::display_graphviz` renders a payload
/// below its node through `Display`.
pub trait Payload: Display + Debug + 'static {}

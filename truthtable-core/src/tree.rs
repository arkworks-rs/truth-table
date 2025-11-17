use std::{any::Any, sync::Arc};

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};

use datafusion::{logical_expr::LogicalPlan, prelude::Expr};
use indexmap::IndexMap;
use std::fmt;

/// The abstraction of a tree structure used in intermediate representations
pub trait Tree<F, MvPCS, UvPCS>: Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    /// The type of nodes contained in this tree.
    type NodeType: Node<F, MvPCS, UvPCS> + ?Sized;
    /// Get the arena that contains all nodes in this tree.
    fn arena(&self) -> &IndexMap<NodeId, Arc<Self::NodeType>>;
    /// Get the root node of this tree.
    fn root(&self) -> &Arc<Self::NodeType>;
    /// Get a reference to a node by its ID.
    fn get_node(&self, node_id: &NodeId) -> Option<&Arc<Self::NodeType>>;
    /// Display the tree in a human-readable format.
    fn graphviz_display(&self) -> String;
}

pub trait Node<F, MvPCS, UvPCS>: Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn children(&self) -> Vec<Arc<dyn Node<F, MvPCS, UvPCS>>>;

    fn name(&self) -> String {
        self.node_id().to_string()
    }

    fn node_id(&self) -> NodeId;

    fn child_edge_labels(&self) -> Vec<Option<String>> {
        self.children().into_iter().map(|_| None).collect()
    }
}
pub fn collect_nodes_for<F, MvPCS, UvPCS>(
    root: &Arc<dyn Node<F, MvPCS, UvPCS>>,
) -> IndexMap<NodeId, Arc<dyn Node<F, MvPCS, UvPCS>>>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn dfs<F, MvPCS, UvPCS>(
        node: &Arc<dyn Node<F, MvPCS, UvPCS>>,
        out: &mut Vec<Arc<dyn Node<F, MvPCS, UvPCS>>>,
    ) where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>> + 'static,
        UvPCS: PCS<F, Poly = LDE<F>> + 'static,
    {
        for child in node.children() {
            dfs::<F, MvPCS, UvPCS>(&child, out);
        }
        out.push(Arc::clone(node));
    }

    let mut nodes = Vec::new();
    dfs::<F, MvPCS, UvPCS>(root, &mut nodes);

    nodes.into_iter().fold(IndexMap::new(), |mut acc, node| {
        acc.insert(node.node_id(), node);
        acc
    })
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum NodeId {
    LP(LogicalPlan),
    Expr(Expr),
    InnerGadget,
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeId::LP(plan) => write!(f, "LogicalPlan({})", plan),
            NodeId::Expr(expr) => write!(f, "Expr({})", expr),
            NodeId::InnerGadget => write!(f, "InnerGadget"),
        }
    }
}

impl NodeId {
    pub fn to_lp(&self) -> Option<&LogicalPlan> {
        match self {
            NodeId::LP(plan) => Some(plan),
            _ => None,
        }
    }

    pub fn to_expr(&self) -> Option<&Expr> {
        match self {
            NodeId::Expr(expr) => Some(expr),
            _ => None,
        }
    }
}

use std::{any::Any, sync::Arc};

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};

use datafusion::{logical_expr::LogicalPlan, prelude::Expr};
use indexmap::IndexMap;
use std::fmt;



pub trait Tree<F, MvPCS, UvPCS>: Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    type NodeType: Node<F, MvPCS, UvPCS> + ?Sized;
    /// Get the arena that contains all nodes in this tree.
    fn arena(&self) -> &IndexMap<NodeId, Arc<Self::NodeType>>;
    /// Get the root node of this tree.
    fn root(&self) -> &Arc<Self::NodeType>;
    /// Get a reference to a node by its ID.
    fn get_node(&self, node_id: &NodeId) -> Option<&Arc<Self::NodeType>>;
    /// Display the tree in a human-readable format.
    fn display(&self) -> String;
}





/// Common interface for a tree node.
pub trait Node<F, MvPCS, UvPCS>: Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    /// Short name for the ProverPlanNode node, such as `FilterNode`.
    /// Children of this node expressed as proof plan trait objects. Leaf nodes
    /// return an empty list.
    fn children(&self) -> Vec<&Arc<dyn Node<F, MvPCS, UvPCS>>>;

    /// A human-readable name for this node
    fn name(&self) -> String {
        self.node_id().to_string()
    }

    /// Classification of this node (used for optional metadata extraction).
    fn node_id(&self) -> NodeId;

    /// Optional human-readable labels for each child edge.
    /// Default implementation leaves every edge unlabeled.
    fn child_edge_labels(&self) -> Vec<Option<String>> {
        self.children().into_iter().map(|_| None).collect()
    }
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

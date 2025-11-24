use std::{any::Any, collections::HashMap, sync::Arc};

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};

use datafusion::{logical_expr::LogicalPlan, prelude::Expr};
use indexmap::IndexMap;
use std::fmt;

use crate::proof_nodes::prover::ProverPlanNode;

/// The abstraction of a tree structure used in intermediate representations
pub trait ProverPlanTree<F, MvPCS, UvPCS>: Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    type Node: ProverPlanNode<F, MvPCS, UvPCS> + ?Sized;

    /// Get the arena that contains all nodes in this tree.
    fn arena(&self) -> &IndexMap<NodeId, Arc<Self::Node>>;
    /// Get the root node of this tree.
    fn root(&self) -> &Arc<Self::Node>;
    /// Get a reference to a node by its ID.
    fn get_node(&self, node_id: &NodeId) -> Option<&Arc<Self::Node>>;
    /// Display the tree in Graphviz DOT format.
    fn display_graphviz(&self, inner: bool) -> String {
        fn escape_label(raw: &str) -> String {
            raw.replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
                .replace('\r', "\\r")
        }

        let mut dot = String::from("digraph Tree {\n");
        dot.push_str("  node [shape=box];\n");
        let mut node_names: HashMap<NodeId, String> = HashMap::new();

        for (idx, (node_id, node)) in self.arena().iter().enumerate() {
            let ident = format!("n{idx}");
            let label = if inner {
                // Include the gadget tree rendering inside the node label.
                let gadget = node.gadget_tree().display_graphviz();
                escape_label(&format!("{}\n{}", node.display(), gadget))
            } else {
                escape_label(&node.display())
            };
            dot.push_str(&format!("  {ident} [label=\"{label}\"];\n"));
            node_names.insert(node_id.clone(), ident);
        }

        for (node_id, node) in self.arena().iter() {
            if let Some(parent_ident) = node_names.get(node_id) {
                let children = node.children();
                let edge_labels = node.child_edge_labels();
                for (idx, child) in children.iter().enumerate() {
                    let child_id = child.node_id();
                    if let Some(child_ident) = node_names.get(&child_id) {
                        if let Some(Some(label)) = edge_labels.get(idx) {
                            let escaped = escape_label(label);
                            dot.push_str(&format!(
                                "  {parent} -> {child} [label=\"{label}\"];\n",
                                parent = parent_ident,
                                child = child_ident,
                                label = escaped,
                            ));
                        } else {
                            dot.push_str(&format!(
                                "  {parent} -> {child};\n",
                                parent = parent_ident,
                                child = child_ident
                            ));
                        }
                    }
                }
            }
        }

        dot.push_str("}\n");
        dot
    }
}

pub fn collect_nodes_for<F, MvPCS, UvPCS>(
    root: &Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
) -> IndexMap<NodeId, Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    fn dfs<F, MvPCS, UvPCS>(
        node: &Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
        out: &mut Vec<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>>,
    ) where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
        UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
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

use crate::id::NodeId;
use std::{
    collections::{HashSet, VecDeque},
    fmt,
    sync::Arc,
};

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};

use crate::verifier_trees::proof_tree::nodes::VerifierNode;

pub struct VerifierProofTreeGraphviz<'a, F, MvPCS, UvPCS> {
    root: &'a Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
}

impl<'a, F, MvPCS, UvPCS> VerifierProofTreeGraphviz<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub fn new(root: &'a Arc<dyn VerifierNode<F, MvPCS, UvPCS>>) -> Self {
        Self { root }
    }

    pub fn graphviz(&self) -> String {
        let mut out = String::new();
        out.push_str("digraph VerifierProofTree {\n");
        out.push_str("  node [shape=box];\n");

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(Arc::clone(self.root));

        while let Some(node) = queue.pop_front() {
            let id = node_ptr_id(&node);
            if !visited.insert(id) {
                continue;
            }

            let (kind, detail) = match node.node_id() {
                NodeId::LP(ref plan) => ("LogicalPlan", plan.display().to_string()),
                NodeId::Expr(ref expr) => ("Expr", expr.to_string()),
            };

            let raw_label = format!("{}\\n{}", kind, detail);
            let label = escape_label(&raw_label);
            out.push_str(&format!("  n{} [label=\"{}\"];\n", id, label));

            for child in node.children() {
                let child_id = node_ptr_id(child);
                out.push_str(&format!("  n{} -> n{};\n", id, child_id));
                queue.push_back(Arc::clone(child));
            }
        }

        out.push_str("}\n");
        out
    }
}

impl<'a, F, MvPCS, UvPCS> fmt::Display for VerifierProofTreeGraphviz<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.graphviz())
    }
}

fn node_ptr_id<F, MvPCS, UvPCS>(node: &Arc<dyn VerifierNode<F, MvPCS, UvPCS>>) -> usize {
    node.as_ref() as *const dyn VerifierNode<F, MvPCS, UvPCS> as *const () as usize
}

fn escape_label(raw: &str) -> String {
    raw.replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

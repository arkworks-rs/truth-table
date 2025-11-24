use super::GadgetTree;
use crate::proof_nodes::prover::ProverGadget;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use std::{
    collections::{HashSet, VecDeque},
    fmt,
    sync::Arc,
};

impl<F, MvPCS, UvPCS> GadgetTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    /// Render the gadget tree as a Graphviz digraph string.
    pub fn display_graphviz(&self) -> String {
        let builder = GadgetTreeGraphviz::new(&self.root);
        builder.graphviz()
    }
}

struct GadgetTreeGraphviz<'a, F, MvPCS, UvPCS> {
    root: &'a Arc<dyn ProverGadget<F, MvPCS, UvPCS>>,
}

impl<'a, F, MvPCS, UvPCS> GadgetTreeGraphviz<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn new(root: &'a Arc<dyn ProverGadget<F, MvPCS, UvPCS>>) -> Self {
        Self { root }
    }

    fn graphviz(&self) -> String {
        let mut out = String::new();
        out.push_str("digraph GadgetTree {\n");
        out.push_str("  node [shape=box];\n");

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(Arc::clone(self.root));

        while let Some(node) = queue.pop_front() {
            let id = node_ptr_id(&node);
            if !visited.insert(id) {
                continue;
            }

            let raw_label = node.display();
            let label = escape_label(&raw_label);
            out.push_str(&format!("  n{} [label=\"{}\"];\n", id, label));

            let children = node.children();
            let edge_labels = node.child_edge_labels();
            for (idx, child) in children.iter().enumerate() {
                let child_id = node_ptr_id(child);
                if let Some(lbl) = edge_labels.get(idx).and_then(|opt| opt.as_ref()) {
                    out.push_str(&format!(
                        "  n{} -> n{} [label=\"{}\"];\n",
                        id,
                        child_id,
                        escape_label(lbl)
                    ));
                } else {
                    out.push_str(&format!("  n{} -> n{};\n", id, child_id));
                }
                queue.push_back(Arc::clone(child));
            }
        }

        out.push_str("}\n");
        out
    }
}

impl<'a, F, MvPCS, UvPCS> fmt::Display for GadgetTreeGraphviz<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.graphviz())
    }
}

fn node_ptr_id<F, MvPCS, UvPCS>(node: &Arc<dyn ProverGadget<F, MvPCS, UvPCS>>) -> usize {
    node.as_ref() as *const dyn ProverGadget<F, MvPCS, UvPCS> as *const () as usize
}

fn escape_label(raw: &str) -> String {
    raw.replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

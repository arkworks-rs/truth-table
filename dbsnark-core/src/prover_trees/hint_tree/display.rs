use crate::id::NodeId;
use std::{
    collections::{HashSet, VecDeque},
    fmt,
    sync::Arc,
};

use crate::prover_trees::proof_tree::nodes::ProverNode;

use super::{ProverHintTree, rows_cols_activated};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::arrow::record_batch::RecordBatch;

fn node_ptr_id<F, MvPCS, UvPCS>(p: &Arc<dyn ProverNode<F, MvPCS, UvPCS>>) -> usize {
    let data_ptr = &**p as *const dyn ProverNode<F, MvPCS, UvPCS> as *const ();
    data_ptr as usize
}

fn esc_label(s: &str) -> String {
    s.replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn hint_rows_cols(batches: Option<&Vec<RecordBatch>>) -> (usize, usize) {
    if let Some(batches) = batches {
        let (rows, cols, _) = rows_cols_activated(batches);
        (rows, cols)
    } else {
        (0, 0)
    }
}

/// Display helper that renders a Graphviz DOT tree for a ProverHintTree.
pub struct DisplayableProverHintTree<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    tree: &'a ProverHintTree<F, MvPCS, UvPCS>,
}

impl<'a, F, MvPCS, UvPCS> DisplayableProverHintTree<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub fn new(tree: &'a ProverHintTree<F, MvPCS, UvPCS>) -> Self {
        Self { tree }
    }

    pub fn graphviz(&self) -> String {
        let mut out = String::new();
        out.push_str("digraph ProverHintTree {\n");
        out.push_str("  node [shape=box];\n");

        let mut visited: HashSet<usize> = HashSet::new();
        let mut q: VecDeque<Arc<dyn ProverNode<F, MvPCS, UvPCS>>> = VecDeque::new();
        q.push_back(self.tree.proof_tree().root());

        while let Some(node) = q.pop_front() {
            let id = node_ptr_id(&node);
            if !visited.insert(id) {
                continue;
            }

            let node_kind = node.node_id();
            let (node_label, variant_label) = match &node_kind {
                NodeId::LP(tree) => ("LogicalPlan", format!("{}", tree.display())),
                NodeId::Expr(expr) => ("Expr", expr.to_string()),
            };

            let hint_keys = {
                let mut entries: Vec<_> = node.hint_generation_plans().into_iter().collect();
                if entries.is_empty() {
                    "<none>".to_string()
                } else {
                    entries.sort_by(|a, b| a.0.cmp(&b.0));
                    entries
                        .into_iter()
                        .map(|(label, _)| {
                            let (rows, cols) =
                                hint_rows_cols(self.tree.batches_for(&node_kind, label.as_str()));
                            format!("{} ( {} rows, {} columns)", label, rows, cols)
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            };

            let raw_label = format!(
                "type: {} ({})\\nhint keys: {}",
                node_label, variant_label, hint_keys
            );
            let label = esc_label(&raw_label);
            out.push_str(&format!("  n{} [label=\"{}\"];\n", id, label));

            for child in node.children() {
                let cid = node_ptr_id(child);
                out.push_str(&format!("  n{} -> n{};\n", id, cid));
                q.push_back(Arc::clone(child));
            }
        }

        out.push_str("}\n");
        out
    }
}

impl<'a, F, MvPCS, UvPCS> fmt::Display for DisplayableProverHintTree<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.graphviz())
    }
}

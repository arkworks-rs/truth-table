use std::{
    collections::{HashSet, VecDeque},
    fmt,
    sync::Arc,
};

use crate::trees::proof_tree::nodes::{ProverNode, ProverNodeNodeId};

use super::{HintTree, rows_cols_activated};
use datafusion::arrow::record_batch::RecordBatch;

fn node_ptr_id(p: &Arc<dyn ProverNode>) -> usize {
    let data_ptr = &**p as *const dyn ProverNode as *const ();
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

/// Display helper that renders a Graphviz DOT tree for a HintTree.
pub struct DisplayableHintTree<'a> {
    tree: &'a HintTree,
}

impl<'a> DisplayableHintTree<'a> {
    pub fn new(tree: &'a HintTree) -> Self {
        Self { tree }
    }

    pub fn graphviz(&self) -> String {
        let mut out = String::new();
        out.push_str("digraph HintTree {\n");
        out.push_str("  node [shape=box];\n");

        let mut visited: HashSet<usize> = HashSet::new();
        let mut q: VecDeque<Arc<dyn ProverNode>> = VecDeque::new();
        q.push_back(self.tree.proof_tree().root());

        while let Some(node) = q.pop_front() {
            let id = node_ptr_id(&node);
            if !visited.insert(id) {
                continue;
            }

            let node_kind = node.node_id();
            let (node_label, variant_label) = match &node_kind {
                ProverNodeNodeId::LP(tree) => ("LogicalPlan", format!("{}", tree.display())),
                ProverNodeNodeId::Expr(expr) => ("Expr", expr.to_string()),
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
                            let (rows, cols) = hint_rows_cols(
                                self.tree.batches_for(&node_kind, label.as_str()),
                            );
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

impl<'a> fmt::Display for DisplayableHintTree<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.graphviz())
    }
}

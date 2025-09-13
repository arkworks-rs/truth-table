use std::collections::{HashSet, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use datafusion::arrow::record_batch::RecordBatch;

use crate::proof_plan::ProofPlan;
use super::WitnessNode;

/// Compute a stable-ish identifier for a plan node for DOT node ids.
fn node_id(p: &Arc<dyn ProofPlan>) -> usize {
    let data_ptr = &**p as *const dyn ProofPlan as *const ();
    data_ptr as usize
}

/// Escape quotes and newlines so they render nicely in Graphviz labels.
fn esc_label(s: &str) -> String {
    s.replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[derive(Clone, Debug)]
/// Compact statistics derived from collected witness batches.
struct ResultStats {
    cols: usize,
    rows: usize,
    col_names: Vec<String>,
}

impl ResultStats {
    /// Aggregate per-node batches into simple size/shape information.
    fn from_batches(batches: &[RecordBatch]) -> Self {
        if let Some(first) = batches.first() {
            let schema = first.schema();
            let cols = schema.fields().len();
            let rows = batches.iter().map(|b| b.num_rows()).sum::<usize>();
            let col_names = schema
                .fields()
                .iter()
                .map(|f| f.name().to_string())
                .collect();
            Self { cols, rows, col_names }
        } else {
            Self { cols: 0, rows: 0, col_names: vec![] }
        }
    }
}

/// Display helper that renders a Graphviz DOT graph for a ProofPlan,
/// annotated with witness result statistics for each node.
///
/// Label includes:
/// - proof node name
/// - node’s relative logical plan (indented)
/// - number of columns and total rows
/// - comma-separated list of column names
pub struct DisplayableWitnessPlan<'a> {
    root: &'a WitnessNode,
}

impl<'a> DisplayableWitnessPlan<'a> {
    /// Create the display wrapper using the root proof node and its witnesses.
    pub fn new(root: &'a WitnessNode) -> Self { Self { root } }

    /// Return Graphviz DOT string for the plan tree, with result stats.
    pub fn graphviz(&self) -> String {
        let mut out = String::new();
        out.push_str("digraph WitnessPlan {\n");
        out.push_str("  node [shape=box];\n");

        let mut visited: HashSet<usize> = HashSet::new();
        let mut q: VecDeque<&WitnessNode> = VecDeque::new();
        q.push_back(self.root);

        while let Some(wn) = q.pop_front() {
            let id = node_id(&wn.node);
            if !visited.insert(id) {
                continue;
            }

            let rel = catch_unwind(AssertUnwindSafe(|| {
                let plan = wn.node.relative_plan();
                format!("{}", plan.display_indent())
            }))
            .unwrap_or_else(|_| "<relative_plan: unavailable>".to_string());

            let stats = ResultStats::from_batches(&wn.result);
            let cols = stats.cols;
            let rows = stats.rows;
            let col_names = if stats.col_names.is_empty() {
                "<none>".to_string()
            } else {
                stats.col_names.join(", ")
            };

            let raw_label = format!(
                "{}\\n{}\\ncols: {}  rows: {}\\ncolumns: {}",
                wn.node.name(),
                rel,
                cols,
                rows,
                col_names
            );
            let label = esc_label(&raw_label);
            out.push_str(&format!("  n{} [label=\"{}\"];\n", id, label));

            for child in &wn.children {
                let cid = node_id(&child.node);
                out.push_str(&format!("  n{} -> n{};\n", id, cid));
                q.push_back(child);
            }
        }

        out.push_str("}\n");
        out
    }
}

impl<'a> std::fmt::Display for DisplayableWitnessPlan<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.graphviz())
    }
}

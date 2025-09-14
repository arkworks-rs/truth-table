use std::{
    collections::{HashSet, VecDeque},
    panic::{catch_unwind, AssertUnwindSafe},
    sync::Arc,
};

use datafusion::arrow::{
    array::{Array, BooleanArray},
    record_batch::RecordBatch,
};

use super::WitnessNode;
use crate::proof_plan::ProofPlan;

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

fn stats_from_batches(batches: &[RecordBatch]) -> (usize, usize, usize, Vec<String>) {
    if let Some(first) = batches.first() {
        let schema = first.schema();
        let cols = schema.fields().len();
        let rows = batches.iter().map(|b| b.num_rows()).sum::<usize>();
        // activator=true count if present
        let mut act_true = 0usize;
        let activator_idx = schema.index_of("activator").ok();
        if let Some(ai) = activator_idx {
            for b in batches {
                if let Ok(i) = b.schema().index_of("activator") {
                    let mask = b
                        .column(i)
                        .as_any()
                        .downcast_ref::<BooleanArray>()
                        .expect("'activator' must be Boolean");
                    for j in 0..mask.len() {
                        if mask.is_valid(j) && mask.value(j) {
                            act_true += 1;
                        }
                    }
                }
            }
        } else {
            act_true = rows;
        }
        let col_names = schema
            .fields()
            .iter()
            .map(|f| f.name().to_string())
            .collect();
        (cols, rows, act_true, col_names)
    } else {
        (0, 0, 0, vec![])
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
    pub fn new(root: &'a WitnessNode) -> Self {
        Self { root }
    }

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

            let (cols, rows, act_true, names) = stats_from_batches(&wn.result);
            let col_names = if names.is_empty() {
                "<none>".to_string()
            } else {
                names.join(", ")
            };

            let raw_label = format!(
                "{}\\n{}\\ncols: {}  rows: {}  act_true: {}\\ncolumns: {}",
                wn.node.name(),
                rel,
                cols,
                rows,
                act_true,
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

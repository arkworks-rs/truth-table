use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use super::{plan_label, rows_cols_activated, WitnessNode};
use crate::ra_proof_plan::{ProofPlan, ProofPlanNodeType};
use datafusion::{arrow::record_batch::RecordBatch, prelude::Expr};

fn node_id(p: &Arc<dyn ProofPlan>) -> usize {
    let data_ptr = &**p as *const dyn ProofPlan as *const ();
    data_ptr as usize
}

fn esc_label(s: &str) -> String {
    s.replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn witness_rows_cols(batches: Option<&Vec<RecordBatch>>) -> (usize, usize) {
    if let Some(batches) = batches {
        let (rows, cols, _) = rows_cols_activated(batches);
        (rows, cols)
    } else {
        (0, 0)
    }
}

/// Display helper that renders a Graphviz DOT graph for a WitnessPlan.
pub struct DisplayableWitnessPlan<'a> {
    root: &'a WitnessNode,
}

impl<'a> DisplayableWitnessPlan<'a> {
    pub fn new(root: &'a WitnessNode) -> Self {
        Self { root }
    }

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

            let (node_label, variant_label) = match wn.node.node_type() {
                ProofPlanNodeType::LogicalPlan(plan) => {
                    ("LogicalPlan", format!("{}", plan.display()))
                },
                ProofPlanNodeType::Expr(expr) => ("Expr", expr.to_string()),
                ProofPlanNodeType::None => ("Unknown", "Unknown".to_string()),
            };

            let witness_keys = {
                let mut entries: Vec<_> = wn.node.witness_generation_plans().into_iter().collect();
                if entries.is_empty() {
                    "<none>".to_string()
                } else {
                    entries.sort_by(|a, b| a.0.cmp(&b.0));
                    entries
                        .into_iter()
                        .map(|(label, _)| {
                            let (rows, cols) = witness_rows_cols(wn.results.get(&label));
                            format!("{} ( {} rows, {} columns)", label, rows, cols)
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            };

            let raw_label = format!(
                "type: {} ({})\\nwitness keys: {}",
                node_label, variant_label, witness_keys
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

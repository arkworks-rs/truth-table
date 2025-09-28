use datafusion::prelude::Expr;
use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use crate::trees::proof_tree::nodes::{ProverNode, ProverNodeNodeId};

/// Display helper for `ProverNode` that renders a Treeviz DOT tree.
/// Similar in spirit to DataFusion's `DisplayableExecutionPlan`.
pub struct DisplayableProverNode<'a> {
    plan: &'a Arc<dyn ProverNode>,
}

impl<'a> DisplayableProverNode<'a> {
    pub fn new(plan: &'a Arc<dyn ProverNode>) -> Self {
        Self { plan }
    }

    /// Return Treeviz DOT string for the plan tree.
    pub fn treeviz(&self) -> String {
        fn node_id(p: &Arc<dyn ProverNode>) -> usize {
            let data_ptr = &**p as *const dyn ProverNode as *const ();
            data_ptr as usize
        }

        fn esc_label(s: &str) -> String {
            s.replace('"', "\\\"")
                .replace('\n', "\\n")
                .replace('\r', "\\r")
        }

        let mut out = String::new();
        out.push_str("ditree ProverNode {\n");
        out.push_str("  node [shape=box];\n");

        let mut visited: HashSet<usize> = HashSet::new();
        let mut q: VecDeque<Arc<dyn ProverNode>> = VecDeque::new();
        q.push_back(Arc::clone(self.plan));

        while let Some(node) = q.pop_front() {
            let id = node_id(&node);
            if !visited.insert(id) {
                continue;
            }

            let (node_label, variant_label) = match node.node_id() {
                ProverNodeNodeId::LP(plan) => ("LogicalPlan", format!("{}", plan.display())),
                ProverNodeNodeId::Expr(expr) => ("Expr", expr.to_string()),
            };
            let witness_keys = {
                let mut keys: Vec<_> = node.hint_generation_plans().keys().cloned().collect();
                if keys.is_empty() {
                    "<none>".to_string()
                } else {
                    keys.sort();
                    keys.join(", ")
                }
            };
            let raw_label = format!(
                "type: {} ({})\\nwitness keys: {}",
                node_label, variant_label, witness_keys
            );
            let label = esc_label(&raw_label);
            out.push_str(&format!("  n{} [label=\"{}\"];\n", id, label));

            for child_ref in node.children() {
                let child = Arc::clone(child_ref);
                let cid = node_id(&child);
                out.push_str(&format!("  n{} -> n{};\n", id, cid));
                q.push_back(child);
            }
        }

        out.push_str("}\n");
        out
    }
}

impl<'a> std::fmt::Display for DisplayableProverNode<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.treeviz())
    }
}

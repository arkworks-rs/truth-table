use crate::ra_proof_plan::{ProofPlan, ProofPlanNodeType};
use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

/// Display helper for `ProofPlan` that renders a Graphviz DOT graph.
/// Similar in spirit to DataFusion's `DisplayableExecutionPlan`.
pub struct DisplayableProofPlan<'a> {
    plan: &'a Arc<dyn ProofPlan>,
}

impl<'a> DisplayableProofPlan<'a> {
    pub fn new(plan: &'a Arc<dyn ProofPlan>) -> Self {
        Self { plan }
    }

    /// Return Graphviz DOT string for the plan tree.
    pub fn graphviz(&self) -> String {
        fn node_id(p: &Arc<dyn ProofPlan>) -> usize {
            let data_ptr = &**p as *const dyn ProofPlan as *const ();
            data_ptr as usize
        }

        fn esc_label(s: &str) -> String {
            s.replace('"', "\\\"")
                .replace('\n', "\\n")
                .replace('\r', "\\r")
        }

        let mut out = String::new();
        out.push_str("digraph ProofPlan {\n");
        out.push_str("  node [shape=box];\n");

        let mut visited: HashSet<usize> = HashSet::new();
        let mut q: VecDeque<Arc<dyn ProofPlan>> = VecDeque::new();
        q.push_back(Arc::clone(self.plan));

        while let Some(node) = q.pop_front() {
            let id = node_id(&node);
            if !visited.insert(id) {
                continue;
            }

            let node_label = match node.node_type() {
                ProofPlanNodeType::LogicalPlan(_) => "LogicalPlan",
                ProofPlanNodeType::Expr(_) => "Expr",
                ProofPlanNodeType::None => "Unknown",
            };
            let witness_keys = {
                let mut keys: Vec<_> = node.witness_generation_plans().keys().cloned().collect();
                if keys.is_empty() {
                    "<none>".to_string()
                } else {
                    keys.sort();
                    keys.join(", ")
                }
            };
            let raw_label = format!("type: {}\\nwitness keys: {}", node_label, witness_keys);
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

impl<'a> std::fmt::Display for DisplayableProofPlan<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.graphviz())
    }
}

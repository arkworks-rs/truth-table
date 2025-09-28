use std::{
    collections::{HashSet, VecDeque},
    fmt,
    sync::Arc,
};

use crate::trees::proof_tree::nodes::{ProverNode, ProverNodeNodeId};

pub struct ProofTreeGraphviz<'a> {
    root: &'a Arc<dyn ProverNode>,
}

impl<'a> ProofTreeGraphviz<'a> {
    pub fn new(root: &'a Arc<dyn ProverNode>) -> Self {
        Self { root }
    }

    pub fn graphviz(&self) -> String {
        let mut out = String::new();
        out.push_str("digraph ProofTree {\n");
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
                ProverNodeNodeId::LP(ref plan) => ("LogicalPlan", plan.display().to_string()),
                ProverNodeNodeId::Expr(ref expr) => ("Expr", expr.to_string()),
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

impl<'a> fmt::Display for ProofTreeGraphviz<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.graphviz())
    }
}

fn node_ptr_id(node: &Arc<dyn ProverNode>) -> usize {
    node.as_ref() as *const dyn ProverNode as *const () as usize
}

fn escape_label(raw: &str) -> String {
    raw.replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

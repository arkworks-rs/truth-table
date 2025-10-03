use std::{
    collections::{HashSet, VecDeque},
    fmt,
    sync::Arc,
};

use crate::trees::proof_tree::nodes::{ProverNode, ProverNodeNodeId};

use super::TrackedTree;
use arithmetic::table::ArithTable;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{logical_expr::LogicalPlan, prelude::Expr};

fn node_ptr_id<F, MvPCS, UvPCS>(node: &Arc<dyn ProverNode<F, MvPCS, UvPCS>>) -> usize {
    node.as_ref() as *const dyn ProverNode<F, MvPCS, UvPCS> as *const () as usize
}

fn esc_label(s: &str) -> String {
    s.replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// Display helper that renders a Treeviz DOT tree for an `TrackedTree`
/// tree.
pub struct DisplayableTrackedTree<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    plan: &'a TrackedTree<F, MvPCS, UvPCS>,
}

impl<'a, F, MvPCS, UvPCS> DisplayableTrackedTree<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub fn new(plan: &'a TrackedTree<F, MvPCS, UvPCS>) -> Self {
        Self { plan }
    }

    pub fn graphviz(&self) -> String {
        let mut out = String::new();
        out.push_str("digraph TrackedTree {\n");
        out.push_str("  node [shape=box];\n");

        let mut visited: HashSet<usize> = HashSet::new();
        let mut q: VecDeque<Arc<dyn ProverNode<F, MvPCS, UvPCS>>> = VecDeque::new();
        q.push_back(self.plan.proof_tree().root());

        while let Some(node) = q.pop_front() {
            let id = node_ptr_id(&node);
            if !visited.insert(id) {
                continue;
            }

            let node_kind = node.node_id();

            let (node_label, variant_label) = match &node_kind {
                ProverNodeNodeId::LP(plan) => ("LogicalPlan", logical_plan_label(plan)),
                ProverNodeNodeId::Expr(expr) => ("Expr", expr_label(expr)),
            };

            let mut table_entries: Vec<(&String, &ArithTable<F, MvPCS, UvPCS>)> = self
                .plan
                .tables_for(&node_kind)
                .map(|m| m.iter().collect())
                .unwrap_or_default();
            table_entries.sort_by(|(a, _), (b, _)| a.cmp(b));

            let table_lines = if table_entries.is_empty() {
                "tables: <none>".to_string()
            } else {
                let mut lines = Vec::with_capacity(table_entries.len() + 1);
                lines.push("tables:".to_string());
                for (label, table) in table_entries {
                    let num_cols = table.num_cols();
                    let num_vars = if num_cols > 0 { table.log_size() } else { 0 };
                    lines.push(format!(
                        "{}: {} vars, {} data cols",
                        label, num_vars, num_cols
                    ));
                }
                lines.join("\n")
            };

            let raw_label = format!("type: {} ({})\\n{}", node_label, variant_label, table_lines);
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

impl<'a, F, MvPCS, UvPCS> fmt::Display for DisplayableTrackedTree<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.graphviz())
    }
}

fn expr_label(expr: &Expr) -> String {
    expr.to_string()
}

fn logical_plan_label(plan: &LogicalPlan) -> String {
    format!("{}", plan.display())
}

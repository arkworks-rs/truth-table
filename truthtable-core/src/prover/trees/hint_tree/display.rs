use super::{ProverHintTree, rows_cols_activated};
use crate::proof_nodes::{id::NodeId, prover::ProverNode};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{arrow::record_batch::RecordBatch, logical_expr::LogicalPlan, prelude::Expr};
use std::{
    collections::{HashSet, VecDeque},
    fmt,
    sync::Arc,
};

fn node_ptr_id<F, MvPCS, UvPCS>(p: &Arc<dyn ProverNode<F, MvPCS, UvPCS>>) -> usize {
    let data_ptr = &**p as *const dyn ProverNode<F, MvPCS, UvPCS> as *const ();
    data_ptr as usize
}

fn esc_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_edge_label(raw: &str) -> String {
    raw.replace('"', "\\\"")
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
                NodeId::LP(plan) => (
                    "LogicalPlan",
                    format!("{} | {}", logical_plan_variant_name(plan), plan.display()),
                ),
                NodeId::Expr(expr) => ("Expr", format!("{} | {}", expr_variant_name(expr), expr)),
                NodeId::None => ("None", "None".to_string()),
            };

            let hint_keys = self
                .tree
                .proof_tree()
                .node(&node_kind)
                .and_then(|original_node| {
                    let mut entries: Vec<_> = original_node
                        .hint_generation_plans(self.tree.proof_tree())
                        .into_iter()
                        .collect();
                    if entries.is_empty() {
                        return None;
                    }
                    entries.sort_by(|a, b| a.0.cmp(&b.0));
                    let lines: Vec<_> = entries
                        .into_iter()
                        .filter_map(|(label, hint_plan)| {
                            if hint_plan.project_materialized().is_none() {
                                return None;
                            }
                            let batches_opt = self.tree.batches_for(&node_kind, label.as_str());
                            let (rows, cols, activated_true) = batches_opt
                                .map(|batches| rows_cols_activated(batches.as_slice()))
                                .unwrap_or((0, 0, None));
                            let activated = activated_true.unwrap_or(rows);
                            Some(format!(
                                "{} ( {} rows, {} activated, {} columns)",
                                label, rows, activated, cols
                            ))
                        })
                        .collect();
                    if lines.is_empty() {
                        None
                    } else {
                        Some(lines.join(", "))
                    }
                });

            let base = format!("{} ({})", node_label, variant_label);
            let base_html = esc_html(&base).replace('\n', "<BR ALIGN=\"LEFT\"/>");

            let label = if let Some(keys) = hint_keys {
                let keys_html = esc_html(&keys).replace('\n', "<BR ALIGN=\"LEFT\"/>");
                format!(
                    "  n{} [label=<{}<BR/><FONT COLOR=\"green\">hint: {}</FONT>>];\n",
                    id, base_html, keys_html
                )
            } else {
                format!("  n{} [label=<{}>];\n", id, base_html)
            };
            out.push_str(&label);

            let children = node.children();
            let edge_labels = node.child_edge_labels();
            for (idx, child) in children.into_iter().enumerate() {
                let cid = node_ptr_id(child);
                if let Some(label) = edge_labels.get(idx).and_then(|opt| opt.as_ref()) {
                    let escaped = escape_edge_label(label);
                    out.push_str(&format!("  n{} -> n{} [label=\"{}\"];\n", id, cid, escaped));
                } else {
                    out.push_str(&format!("  n{} -> n{};\n", id, cid));
                }
                q.push_back(Arc::clone(child));
            }
        }

        out.push_str("}\n");
        out
    }
}

fn expr_variant_name(expr: &Expr) -> &'static str {
    match expr {
        Expr::Alias(_) => "Alias",
        Expr::Column(_) => "Column",
        Expr::ScalarVariable(..) => "ScalarVariable",
        Expr::Literal(_) => "Literal",
        Expr::BinaryExpr(_) => "BinaryExpr",
        Expr::Like(_) => "Like",
        Expr::SimilarTo(_) => "SimilarTo",
        Expr::Not(_) => "Not",
        Expr::IsNotNull(_) => "IsNotNull",
        Expr::IsNull(_) => "IsNull",
        Expr::IsTrue(_) => "IsTrue",
        Expr::IsFalse(_) => "IsFalse",
        Expr::IsUnknown(_) => "IsUnknown",
        Expr::IsNotTrue(_) => "IsNotTrue",
        Expr::IsNotFalse(_) => "IsNotFalse",
        Expr::IsNotUnknown(_) => "IsNotUnknown",
        Expr::Negative(_) => "Negative",
        Expr::Between(_) => "Between",
        Expr::Case(_) => "Case",
        Expr::Cast(_) => "Cast",
        Expr::TryCast(_) => "TryCast",
        Expr::ScalarFunction(_) => "ScalarFunction",
        Expr::AggregateFunction(_) => "AggregateFunction",
        Expr::WindowFunction(_) => "WindowFunction",
        Expr::InList(_) => "InList",
        Expr::Exists(_) => "Exists",
        Expr::InSubquery(_) => "InSubquery",
        Expr::ScalarSubquery(_) => "ScalarSubquery",
        Expr::Wildcard { .. } => "Wildcard",
        Expr::GroupingSet(_) => "GroupingSet",
        Expr::Placeholder(_) => "Placeholder",
        Expr::OuterReferenceColumn(..) => "OuterReferenceColumn",
        Expr::Unnest(_) => "Unnest",
    }
}

fn logical_plan_variant_name(plan: &LogicalPlan) -> &'static str {
    match plan {
        LogicalPlan::Projection(_) => "Projection",
        LogicalPlan::Filter(_) => "Filter",
        LogicalPlan::Window(_) => "Window",
        LogicalPlan::Aggregate(_) => "Aggregate",
        LogicalPlan::Sort(_) => "Sort",
        LogicalPlan::Join(_) => "Join",
        LogicalPlan::Repartition(_) => "Repartition",
        LogicalPlan::Union(_) => "Union",
        LogicalPlan::TableScan(_) => "TableScan",
        LogicalPlan::EmptyRelation(_) => "EmptyRelation",
        LogicalPlan::Subquery(_) => "Subquery",
        LogicalPlan::SubqueryAlias(_) => "SubqueryAlias",
        LogicalPlan::Limit(_) => "Limit",
        LogicalPlan::Statement(_) => "Statement",
        LogicalPlan::Values(_) => "Values",
        LogicalPlan::Explain(_) => "Explain",
        LogicalPlan::Analyze(_) => "Analyze",
        LogicalPlan::Extension(_) => "Extension",
        LogicalPlan::Distinct(_) => "Distinct",
        LogicalPlan::Dml(_) => "Dml",
        LogicalPlan::Ddl(_) => "Ddl",
        LogicalPlan::Copy(_) => "Copy",
        LogicalPlan::DescribeTable(_) => "DescribeTable",
        LogicalPlan::Unnest(_) => "Unnest",
        LogicalPlan::RecursiveQuery(_) => "RecursiveQuery",
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

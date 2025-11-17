use super::ProverTrackedTree;
use crate::proof_nodes::{id::NodeId, prover::ProverPlanNode};
use arithmetic::table::TrackedTable;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{logical_expr::LogicalPlan, prelude::Expr};
use std::{
    collections::{HashSet, VecDeque},
    fmt,
    sync::Arc,
};

fn node_ptr_id<F, MvPCS, UvPCS>(node: &Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>) -> usize {
    node.as_ref() as *const dyn ProverPlanNode<F, MvPCS, UvPCS> as *const () as usize
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

/// Display helper that renders a Treeviz DOT tree for an `ProverTrackedTree`
/// tree.
pub struct DisplayableProverTrackedTree<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    plan: &'a ProverTrackedTree<F, MvPCS, UvPCS>,
}

impl<'a, F, MvPCS, UvPCS> DisplayableProverTrackedTree<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub fn new(plan: &'a ProverTrackedTree<F, MvPCS, UvPCS>) -> Self {
        Self { plan }
    }

    pub fn graphviz(&self) -> String {
        todo!()
        // let mut out = String::new();
        // out.push_str("digraph ProverTrackedTree {\n");
        // out.push_str("  node [shape=box];\n");

        // let mut visited: HashSet<usize> = HashSet::new();
        // let mut q: VecDeque<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>> = VecDeque::new();
        // q.push_back(self.plan.proof_tree().root());

        // while let Some(node) = q.pop_front() {
        //     let id = node_ptr_id(&node);
        //     if !visited.insert(id) {
        //         continue;
        //     }

        //     let node_kind = node.node_id();

        //     let (node_label, variant_label) = match &node_kind {
        //         NodeId::LP(plan) => (
        //             "LogicalPlan",
        //             format!("{} | {}", logical_plan_variant_name(plan), plan.display()),
        //         ),
        //         NodeId::Expr(expr) => (
        //             "Expr",
        //             format!("{} | {}", expr_variant_name(expr), expr_detail(expr)),
        //         ),
        //         NodeId::None => ("None", "None".to_string()),
        //     };

        //     let mut table_entries: Vec<(&String, &TrackedTable<F, MvPCS, UvPCS>)> = self
        //         .plan
        //         .tracked_tables_for(&node_kind)
        //         .map(|m| m.iter().collect())
        //         .unwrap_or_default();
        //     table_entries.sort_by(|(a, _), (b, _)| a.cmp(b));

        //     let table_lines = if table_entries.is_empty() {
        //         None
        //     } else {
        //         let mut lines = Vec::with_capacity(table_entries.len() + 1);
        //         lines.push("Tracked tables:".to_string());
        //         for (label, table) in table_entries {
        //             let num_total_cols = table.num_total_tracked_cols();
        //             let num_vars = if num_total_cols > 0 {
        //                 table.log_size()
        //             } else {
        //                 0
        //             };
        //             lines.push(format!(
        //                 "{}: {} vars, {} data cols",
        //                 label, num_vars, num_total_cols
        //             ));
        //         }
        //         Some(lines.join("\n"))
        //     };

        //     let base = format!("{} ({})", node_label, variant_label);
        //     let base_html = esc_html(&base).replace('\n', "<BR ALIGN=\"LEFT\"/>");

        //     let label = if let Some(lines) = table_lines {
        //         let lines_html = esc_html(&lines).replace('\n', "<BR ALIGN=\"LEFT\"/>");
        //         format!(
        //             "  n{} [label=<{}<BR/><FONT COLOR=\"blue\">{}</FONT>>];\n",
        //             id, base_html, lines_html
        //         )
        //     } else {
        //         format!("  n{} [label=<{}>];\n", id, base_html)
        //     };
        //     out.push_str(&label);

        //     let children = node.children();
        //     let edge_labels = node.child_edge_labels();
        //     for (idx, child) in children.into_iter().enumerate() {
        //         let cid = node_ptr_id(child);
        //         if let Some(label) = edge_labels.get(idx).and_then(|opt| opt.as_ref()) {
        //             let escaped = escape_edge_label(label);
        //             out.push_str(&format!("  n{} -> n{} [label=\"{}\"];\n", id, cid, escaped));
        //         } else {
        //             out.push_str(&format!("  n{} -> n{};\n", id, cid));
        //         }
        //         q.push_back(Arc::clone(child));
        //     }
        // }

        // out.push_str("}\n");
        // out
    }
}

impl<'a, F, MvPCS, UvPCS> fmt::Display for DisplayableProverTrackedTree<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.graphviz())
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
        Expr::GroupingSet(_) => "GroupingSet",
        Expr::Placeholder(_) => "Placeholder",
        Expr::OuterReferenceColumn(..) => "OuterReferenceColumn",
        Expr::Unnest(_) => "Unnest",
        _ => "Other",
    }
}

fn expr_detail(expr: &Expr) -> String {
   todo!()
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

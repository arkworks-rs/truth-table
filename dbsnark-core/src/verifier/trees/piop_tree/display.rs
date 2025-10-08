use crate::{id::NodeId, verifier::nodes::VerifierNode};
use std::{
    collections::{HashSet, VecDeque},
    fmt,
    sync::Arc,
};

use super::VerifierPIOPTree;
use arithmetic::table_oracle::TrackedTableOracle;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{logical_expr::LogicalPlan, prelude::Expr};

fn node_ptr_id<F, MvPCS, UvPCS>(node: &Arc<dyn VerifierNode<F, MvPCS, UvPCS>>) -> usize {
    node.as_ref() as *const dyn VerifierNode<F, MvPCS, UvPCS> as *const () as usize
}

fn esc_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Display helper that renders a Treeviz DOT tree for a `VerifierPIOPTree`
/// tree.
pub struct DisplayableVerifierPIOPTree<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    plan: &'a VerifierPIOPTree<F, MvPCS, UvPCS>,
}

impl<'a, F, MvPCS, UvPCS> DisplayableVerifierPIOPTree<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub fn new(plan: &'a VerifierPIOPTree<F, MvPCS, UvPCS>) -> Self {
        Self { plan }
    }

    pub fn graphviz(&self) -> String {
        let mut out = String::new();
        out.push_str("digraph VerifierPIOPTree {\n");
        out.push_str("  node [shape=box];\n");

        let mut visited: HashSet<usize> = HashSet::new();
        let mut q: VecDeque<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> = VecDeque::new();
        q.push_back(self.plan.proof_tree().root());

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
            };

            let mut table_entries: Vec<(&String, &TrackedTableOracle<F, MvPCS, UvPCS>)> = self
                .plan
                .tracked_table_oracles_for(&node_kind)
                .map(|m| m.iter().collect())
                .unwrap_or_default();
            table_entries.sort_by(|(a, _), (b, _)| a.cmp(b));

            let table_lines = if table_entries.is_empty() {
                None
            } else {
                let mut lines = Vec::with_capacity(table_entries.len() + 1);
                lines.push("Tracked tables:".to_string());
                for (label, table) in table_entries {
                    let num_total_cols = table.num_total_tracked_col_oracles();
                    let log_size = if num_total_cols > 0 {
                        table.log_size()
                    } else {
                        0
                    };
                    lines.push(format!(
                        "{}: {} log_size, {} data cols",
                        label, log_size, num_total_cols
                    ));
                }
                Some(lines.join("\n"))
            };

            let base = format!("{} ({})", node_label, variant_label);
            let base_html = esc_html(&base).replace('\n', "<BR ALIGN=\"LEFT\"/>");

            let label = if let Some(lines) = table_lines {
                let lines_html = esc_html(&lines).replace('\n', "<BR ALIGN=\"LEFT\"/>");
                format!(
                    "  n{} [label=<{}<BR/><FONT COLOR=\"green\">{}</FONT>>];\n",
                    id, base_html, lines_html
                )
            } else {
                format!("  n{} [label=<{}>];\n", id, base_html)
            };
            out.push_str(&label);

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

impl<'a, F, MvPCS, UvPCS> fmt::Display for DisplayableVerifierPIOPTree<'a, F, MvPCS, UvPCS>
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

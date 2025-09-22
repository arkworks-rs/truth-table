use crate::ra_proof_plan::{ProofPlan, ProofPlanNodeType};
use datafusion::{
    logical_expr::{self as df, LogicalPlan},
    prelude::Expr,
};
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

        fn logical_plan_variant_name(plan: &LogicalPlan) -> &'static str {
            match plan {
                df::LogicalPlan::Projection(_) => "Projection",
                df::LogicalPlan::Filter(_) => "Filter",
                df::LogicalPlan::Window(_) => "Window",
                df::LogicalPlan::Aggregate(_) => "Aggregate",
                df::LogicalPlan::Sort(_) => "Sort",
                df::LogicalPlan::Join(_) => "Join",
                df::LogicalPlan::Repartition(_) => "Repartition",
                df::LogicalPlan::Union(_) => "Union",
                df::LogicalPlan::TableScan(_) => "TableScan",
                df::LogicalPlan::EmptyRelation(_) => "EmptyRelation",
                df::LogicalPlan::Subquery(_) => "Subquery",
                df::LogicalPlan::SubqueryAlias(_) => "SubqueryAlias",
                df::LogicalPlan::Limit(_) => "Limit",
                df::LogicalPlan::Statement(_) => "Statement",
                df::LogicalPlan::Values(_) => "Values",
                df::LogicalPlan::Explain(_) => "Explain",
                df::LogicalPlan::Analyze(_) => "Analyze",
                df::LogicalPlan::Extension(_) => "Extension",
                df::LogicalPlan::Distinct(_) => "Distinct",
                df::LogicalPlan::Dml(_) => "Dml",
                df::LogicalPlan::Ddl(_) => "Ddl",
                df::LogicalPlan::Copy(_) => "Copy",
                df::LogicalPlan::DescribeTable(_) => "DescribeTable",
                df::LogicalPlan::Unnest(_) => "Unnest",
                df::LogicalPlan::RecursiveQuery(_) => "RecursiveQuery",
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

            let (node_label, variant_label) = match node.node_type() {
                ProofPlanNodeType::LogicalPlan(plan) => {
                    ("LogicalPlan", logical_plan_variant_name(&plan))
                },
                ProofPlanNodeType::Expr(expr) => ("Expr", expr_variant_name(&expr)),
                ProofPlanNodeType::None => ("Unknown", "Unknown"),
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

impl<'a> std::fmt::Display for DisplayableProofPlan<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.graphviz())
    }
}

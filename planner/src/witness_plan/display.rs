use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use super::{plan_label, rows_cols_activated, WitnessNode};
use crate::ra_proof_plan::{ProofPlan, ProofPlanNodeType};
use datafusion::{
    arrow::record_batch::RecordBatch,
    logical_expr::{self as df, LogicalPlan},
    prelude::Expr,
};

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
                    ("LogicalPlan", logical_plan_variant_name(&plan))
                },
                ProofPlanNodeType::Expr(expr) => ("Expr", expr_variant_name(&expr)),
                ProofPlanNodeType::None => ("Unknown", "Unknown"),
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

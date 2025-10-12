use crate::proof_nodes::{id::NodeId, prover::ProverNode};
use datafusion::logical_expr::Expr;
use std::{
    collections::{HashSet, VecDeque},
    fmt,
    sync::Arc,
};

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};

pub struct ProverProofTreeGraphviz<'a, F, MvPCS, UvPCS> {
    root: &'a Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
}

impl<'a, F, MvPCS, UvPCS> ProverProofTreeGraphviz<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub fn new(root: &'a Arc<dyn ProverNode<F, MvPCS, UvPCS>>) -> Self {
        Self { root }
    }

    pub fn graphviz(&self) -> String {
        let mut out = String::new();
        out.push_str("digraph ProverProofTree {\n");
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
                NodeId::LP(ref plan) => (String::from("LogicalPlan"), plan.display().to_string()),
                NodeId::Expr(ref expr) => (
                    format!("Expr ({})", expr_variant_name(expr)),
                    expr.to_string(),
                ),
                NodeId::None => ("None".to_string(), "None".to_string()),
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

impl<'a, F, MvPCS, UvPCS> fmt::Display for ProverProofTreeGraphviz<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.graphviz())
    }
}

fn node_ptr_id<F, MvPCS, UvPCS>(node: &Arc<dyn ProverNode<F, MvPCS, UvPCS>>) -> usize {
    node.as_ref() as *const dyn ProverNode<F, MvPCS, UvPCS> as *const () as usize
}

fn escape_label(raw: &str) -> String {
    raw.replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
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

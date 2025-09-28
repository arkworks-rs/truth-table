//! The proof plan module contains a set of tools to build a proof plan from a
//! DataFusion logical plan.
pub mod display;
pub mod exprs;
pub mod lps;

use std::{any::Any, collections::HashMap, sync::Arc};

use arithmetic::table::ArithTable;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{
    logical_expr::{self as df, LogicalPlan},
    prelude::{Expr, SessionContext},
};

use crate::trees::{
    arithmetized_tree::{self, ArithmetizedTree},
    proof_tree::nodes::exprs::{AliasExprNode, BinaryExprNode, ColumnExprNode, LiteralExprNode},
};

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum ProverNodeNodeId {
    LP(LogicalPlan),
    Expr(Expr),
}

impl std::fmt::Display for ProverNodeNodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProverNodeNodeId::LP(plan) => write!(f, "LogicalPlan({})", plan.to_string()),
            ProverNodeNodeId::Expr(expr) => write!(f, "Expr({})", expr),
        }
    }
}

/// Common interface for a proof plan node.
///
/// A proof plan is a tree of nodes, where each node represents a proof unit.
// TODO: also add a VerifierNode
// TODO: hint generation, materialized witness vs virtual witness
pub trait ProverNode<F, MvPCS, UvPCS>: Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    /// Constructs a proof plan node from a DataFusion expression and its parent
    /// logical plan.
    fn from_expr(ctx: &SessionContext, expr: Expr, parent_logical_plan: LogicalPlan) -> Self
    where
        Self: Sized,
    {
        unimplemented!()
    }
    /// Constructs a proof plan node from a DataFusion logical plan.
    fn from_logical_plan(ctx: &SessionContext, plan: LogicalPlan) -> Self
    where
        Self: Sized,
    {
        unimplemented!()
    }

    /// Returns the Proof plan as `Any` so that it can be downcast to a specific
    /// implementation.
    fn as_any(&self) -> &dyn Any;

    /// Short name for the ProverNode node, such as `FilterNode`.
    /// Children of this node expressed as proof plan trait objects. Leaf nodes
    /// return an empty list.
    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>>;

    /// Appends all the descendants of this node in 'post-order' to the given
    /// mutable vector.
    /// Post-order over descendants: for each child, traverse its descendants
    /// first, then push the child; the current node itself is not included.
    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
    }

    /// A human-readable name for this node
    fn name(&self) -> String {
        self.node_id().to_string()
    }

    /// Classification of this node (used for optional metadata extraction).
    fn node_id(&self) -> ProverNodeNodeId;

    /// A map of named logical plans that can be used to materialize witnesses
    /// for this node. Logical plan nodes typically return a single entry with
    /// the key `"output_plan"`.
    fn hint_generation_plans(&self) -> HashMap<String, LogicalPlan> {
        HashMap::new()
    }

    /// Complete the piop plan
    fn append_virtual_witness(
        &self,
        _arithmetized_tree: &ArithmetizedTree<F, MvPCS, UvPCS>,
        _node_arithmetized_tables: &mut HashMap<
            ProverNodeNodeId,
            HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
        >,
    ) {
        todo!()
    }
}

pub fn output_logical_plan<F, MvPCS, UvPCS>(
    node: &Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
) -> Option<LogicalPlan>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    node.hint_generation_plans()
        .into_iter()
        .find_map(|(label, plan)| {
            if label == "output_plan" {
                Some(plan)
            } else {
                None
            }
        })
}

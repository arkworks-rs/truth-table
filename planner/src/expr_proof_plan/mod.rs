//! The proof plan module contains a set of tools to build a proof plan from a
//! DataFusion logical plan.
pub mod nodes;

pub use nodes::*;

use std::{any::Any, sync::Arc};

use datafusion::sql::sqlparser::ast::Expr;

/// Common interface for a proof plan node
///
/// A proof plan is a tree of nodes, where each node represents a proof unit.
pub trait ExprProofPlan: Any + Send + Sync {
    /// Returns the Proof plan as Any so that it can be downcast to a specific
    /// implementation.
    fn as_any(&self) -> &dyn Any;
    /// Short name for the RAProofPlan node, such as ‘FilterNode’.
    fn name(&self) -> &str;
    /// The node’s operator applied to its children’s relative expressions.
    fn rel_expr(&self) -> Expr;
    /// A fully “unrolled” expression that starts at base table columns and
    fn absolute_expr(&self) -> Expr;
    /// Get a list of children RAProofPlans that act as inputs to this plan. The
    /// returned list will be empty for leaf nodes such as scans, will contain a
    /// single value for unary nodes, or two values for binary nodes (such as
    /// joins).
    fn children(&self) -> Vec<&Arc<dyn ExprProofPlan>>;
}

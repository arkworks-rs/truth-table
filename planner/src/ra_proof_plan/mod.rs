//! The proof plan module contains a set of tools to build a proof plan from a
//! DataFusion logical plan.
pub mod display;
pub mod expr_nodes;
pub mod logical_plan_nodes;

use std::{any::Any, collections::HashMap, sync::Arc};

use datafusion::{
    logical_expr::{self as df, LogicalPlan},
    prelude::{Expr, SessionContext},
};

pub use expr_nodes::*;
pub use logical_plan_nodes::*;

#[derive(Clone)]
pub enum ProofPlanNodeType {
    LogicalPlan(LogicalPlan),
    Expr(Expr),
    None,
}

/// Common interface for a proof plan node.
///
/// A proof plan is a tree of nodes, where each node represents a proof unit.
pub trait ProofPlan: Any + Send + Sync {
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

    /// Short name for the ProofPlan node, such as `FilterNode`.
    /// Children of this node expressed as proof plan trait objects. Leaf nodes
    /// return an empty list.
    fn children(&self) -> Vec<&Arc<dyn ProofPlan>>;

    /// Classification of this node (used for optional metadata extraction).
    fn node_type(&self) -> ProofPlanNodeType {
        ProofPlanNodeType::None
    }

    /// A map of named logical plans that can be used to materialize witnesses
    /// for this node. Logical plan nodes typically return a single entry with
    /// the key `"output_plan"`.
    fn witness_generation_plans(&self) -> HashMap<String, LogicalPlan> {
        HashMap::new()
    }
}

/// Appends all the descendants of this node in 'post-order' to the given
/// mutable vector.
/// Post-order: children first, then self.
pub fn append_sorted_descendants(node: Arc<dyn ProofPlan>, out: &mut Vec<Arc<dyn ProofPlan>>) {
    for child in node.children() {
        append_sorted_descendants(Arc::clone(child), out);
    }
    out.push(node);
}

/// Returns all descendants including root in post-order.
pub fn sorted_descendants(root: Arc<dyn ProofPlan>) -> Vec<Arc<dyn ProofPlan>> {
    let mut v = Vec::new();
    append_sorted_descendants(root, &mut v);
    v
}

/// Build a `ProofPlan` tree from a DataFusion `LogicalPlan`.
#[tracing::instrument(name = "logical_to_proof_plan", skip(ctx, plan))]
pub fn logical_to_proof_plan(ctx: &SessionContext, plan: &LogicalPlan) -> Arc<dyn ProofPlan> {
    match plan {
        df::LogicalPlan::TableScan(_ts) => {
            Arc::new(TableScanNode::from_logical_plan(ctx, plan.clone()))
        },
        df::LogicalPlan::Values(_vals) => todo!(),
        df::LogicalPlan::Projection(_) => {
            Arc::new(ProjectionNode::from_logical_plan(ctx, plan.clone()))
        },
        df::LogicalPlan::Filter(_) => Arc::new(FilterNode::from_logical_plan(ctx, plan.clone())),
        df::LogicalPlan::Window(_w) => todo!(),
        df::LogicalPlan::Aggregate(_aggr) => todo!(),
        df::LogicalPlan::Sort(_s) => todo!(),
        df::LogicalPlan::Repartition(_r) => todo!(),
        df::LogicalPlan::Analyze(_a) => todo!(),
        df::LogicalPlan::Distinct(_d) => todo!(),
        df::LogicalPlan::Subquery(_sq) => todo!(),
        df::LogicalPlan::SubqueryAlias(_sqa) => todo!(),
        df::LogicalPlan::Union(_u) => todo!(),
        df::LogicalPlan::Extension(_ext) => todo!(),
        df::LogicalPlan::Join(_j) => todo!(),
        df::LogicalPlan::Limit(l) => todo!(),
        _ => panic!(),
    }
}

pub fn expr_to_proof_plan(
    ctx: &SessionContext,
    expr: Expr,
    input_plan: &LogicalPlan,
) -> Arc<dyn ProofPlan> {
    match expr.clone() {
        Expr::Alias(_) => todo!(),
        Expr::Column(_) => Arc::new(ColumnExprNode::from_expr(ctx, expr, input_plan.clone())),
        Expr::ScalarVariable(..) => todo!(),
        Expr::Literal(_) => Arc::new(LiteralExprNode::from_expr(ctx, expr, input_plan.clone())),
        Expr::BinaryExpr(_) => Arc::new(BinaryExprNode::from_expr(ctx, expr, input_plan.clone())),
        Expr::Like(_) => todo!(),
        Expr::SimilarTo(_) => todo!(),
        Expr::Not(_) => todo!(),
        Expr::IsNotNull(_) => todo!(),
        Expr::IsNull(_) => todo!(),
        Expr::IsTrue(_) => todo!(),
        Expr::IsFalse(_) => todo!(),
        Expr::IsUnknown(_) => todo!(),
        Expr::IsNotTrue(_) => todo!(),
        Expr::IsNotFalse(_) => todo!(),
        Expr::IsNotUnknown(_) => todo!(),
        Expr::Negative(_) => todo!(),
        Expr::Between(_) => todo!(),
        Expr::Case(_) => todo!(),
        Expr::Cast(_) => todo!(),
        Expr::TryCast(_) => todo!(),
        Expr::ScalarFunction(_) => todo!(),
        Expr::AggregateFunction(_) => todo!(),
        Expr::WindowFunction(_) => todo!(),
        Expr::InList(_) => todo!(),
        Expr::Exists(_) => todo!(),
        Expr::InSubquery(_) => todo!(),
        Expr::ScalarSubquery(_) => todo!(),
        Expr::Wildcard { .. } => todo!(),
        Expr::GroupingSet(_) => todo!(),
        Expr::Placeholder(_) => todo!(),
        Expr::OuterReferenceColumn(..) => todo!(),
        Expr::Unnest(_) => todo!(),
        _ => todo!(),
    }
}

pub fn output_logical_plan(node: &Arc<dyn ProofPlan>) -> Option<LogicalPlan> {
    node.witness_generation_plans()
        .into_iter()
        .find_map(|(label, plan)| {
            if label == "output_plan" {
                Some(plan)
            } else {
                None
            }
        })
        .or_else(|| relative_plan_opt(node))
}

/// Best-effort access to a node's relative logical plan for display/debugging.
pub fn relative_plan_opt(node: &Arc<dyn ProofPlan>) -> Option<LogicalPlan> {
    match node.node_type() {
        ProofPlanNodeType::LogicalPlan(plan) => Some(plan),
        _ => node
            .witness_generation_plans()
            .into_iter()
            .find_map(|(label, plan)| {
                if label == "relative_output" {
                    Some(plan)
                } else {
                    None
                }
            }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ra_proof_plan::display::DisplayableProofPlan;
    use datafusion::prelude::{ParquetReadOptions, SessionContext};
    use tpch_data::test_data_path;

    #[tokio::test]
    async fn logical_to_proof_plan_graphviz() {
        // Build logical plan from hardcoded SQL using VALUES
        let ctx = SessionContext::new();

        let parquet_path = test_data_path("lineitem.parquet");
        assert!(
            parquet_path.exists(),
            "Missing Parquet at {:?}",
            parquet_path
        );
        ctx.register_parquet(
            "lineitem",
            parquet_path.to_str().unwrap(),
            ParquetReadOptions::default(),
        )
        .await
        .unwrap();

        let sql = r#"
            SELECT l_discount FROM lineitem WHERE l_quantity = 2
        "#;
        let df = ctx.sql(sql).await.unwrap();
        let plan = df.into_unoptimized_plan();
        // Display the DataFusion logical plan as Graphviz
        let logical_dot = format!("{}", plan.display_graphviz());
        println!("LogicalPlan DOT:\n{}", logical_dot);

        // Convert to proof plan
        let proof_plan = logical_to_proof_plan(&ctx, &plan);

        // Display our proof plan as Graphviz
        let proof_dot = format!("{}", DisplayableProofPlan::new(&proof_plan));
        println!("ProofPlan DOT:\n{}", proof_dot);
    }
}

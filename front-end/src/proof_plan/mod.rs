//! The proof plan module contains a set of tools to build a proof plan from a
//! DataFusion logical plan.
pub mod display;
pub mod nodes;
use std::{any::Any, sync::Arc};

use datafusion::{
    logical_expr as df,
    logical_expr::{ExprSchemable, LogicalPlan},
    prelude::SessionContext,
};
use nodes::*;

/// Common interface for a proof plan node
///
/// A proof plan is a tree of nodes, where each node represents a proof unit.
pub trait ProofPlan: Any + Send + Sync {
    /// Returns the Proof plan as Any so that it can be downcast to a specific
    /// implementation.
    fn as_any(&self) -> &dyn Any;
    /// Short name for the ProofPlan node, such as ‘FilterNode’.
    fn name(&self) -> &str;
    /// A fully “unrolled” logical plan that starts at base table scans and
    /// applies every ancestor operator up to this node. This  makes each
    /// node independently executable and suitable for parallel
    fn absolute_plan(&self) -> LogicalPlan;
    /// The node’s operator applied to its children’s relative  plans
    /// (traditional top-down planning)
    fn relative_plan(&self) -> LogicalPlan;
    /// Get a list of children ProofPlans that act as inputs to this plan. The
    /// returned list will be empty for leaf nodes such as scans, will contain a
    /// single value for unary nodes, or two values for binary nodes (such as
    /// joins).
    fn children(&self) -> Vec<&Arc<dyn ProofPlan>>;
}

/// Appends all the descendants of this node in 'post-order' to the given
/// mutable vector.
// Post-order: children first, then self
pub fn append_sorted_descendants(node: Arc<dyn ProofPlan>, out: &mut Vec<Arc<dyn ProofPlan>>) {
    for child in node.children() {
        // child: &Arc<dyn ProofPlan>  → clone to recurse
        append_sorted_descendants(Arc::clone(child), out);
    }
    out.push(node);
}
// push this node last (post-order)
// clone Arc<Self> then coerce to Arc<dyn ProofPlan>
pub fn sorted_descendants(root: Arc<dyn ProofPlan>) -> Vec<Arc<dyn ProofPlan>> {
    let mut v = Vec::new();
    append_sorted_descendants(root, &mut v);
    v
}

/// Build a `ProofPlan` tree from a DataFusion `LogicalPlan`
pub fn logical_to_proof_plan(ctx: &SessionContext, plan: &LogicalPlan) -> Arc<dyn ProofPlan> {
    match plan {
        df::LogicalPlan::TableScan(_ts) => Arc::new(TableScanNode::new(ctx, plan.clone())),
        df::LogicalPlan::Values(_vals) => todo!(),
        df::LogicalPlan::Projection(p) => Arc::new(ProjectionNode::new(
            ctx,
            p.expr.clone(),
            logical_to_proof_plan(ctx, &p.input),
        )),
        df::LogicalPlan::Filter(f) => Arc::new(FilterNode::new(
            ctx,
            f.predicate.clone(),
            logical_to_proof_plan(ctx, &f.input),
        )),
        df::LogicalPlan::Window(w) => todo!(),
        df::LogicalPlan::Aggregate(aggr) => todo!(),
        df::LogicalPlan::Sort(s) => todo!(),
        df::LogicalPlan::Repartition(r) => todo!(),
        df::LogicalPlan::Analyze(a) => todo!(),
        df::LogicalPlan::Distinct(d) => todo!(),
        df::LogicalPlan::Subquery(sq) => todo!(),
        df::LogicalPlan::SubqueryAlias(sqa) => todo!(),
        df::LogicalPlan::Union(u) => todo!(),
        df::LogicalPlan::Extension(_ext) => todo!(),
        df::LogicalPlan::Join(j) => todo!(),
        df::LogicalPlan::Limit(l) => todo!(),
        _ => panic!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{proof_plan::display::DisplayableProofPlan, test_utils::imdb_parquet_path};
    use datafusion::prelude::{ParquetReadOptions, SessionContext};

    #[tokio::test]
    async fn logical_to_proof_plan_graphviz() {
        // Build logical plan from hardcoded SQL using VALUES
        let ctx = SessionContext::new();

        let parquet_path = imdb_parquet_path("title-sanitized.parquet");
        assert!(
            parquet_path.exists(),
            "Missing Parquet at {:?}",
            parquet_path
        );
        ctx.register_parquet(
            "titles",
            parquet_path.to_str().unwrap(),
            ParquetReadOptions::default(),
        )
        .await
        .unwrap();

        let sql = r#"
            SELECT * FROM titles WHERE PRODUCTION_YEAR = 2000
        "#;
        let df = ctx.sql(sql).await.unwrap();
        let plan = df.into_unoptimized_plan();
        // Display the DataFusion logical plan as Graphviz
        let logical_dot = format!("{}", plan.display_graphviz());
        println!("LogicalPlan DOT:\n{}", logical_dot);

        // Convert to optimized proof plan
        let proof_root = logical_to_proof_plan(&ctx, &plan);

        // Display our proof plan as Graphviz
        let proof_dot = format!("{}", DisplayableProofPlan::new(&proof_root));
        println!("ProofPlan DOT:\n{}", proof_dot);
    }
}

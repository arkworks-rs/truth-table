use std::sync::Arc;

use datafusion::{
    logical_expr::{
        self, LogicalPlan, {self as df},
    },
    prelude::{Expr, SessionContext},
};

use crate::nodes::{
    ProverNode,
    lps::{FilterNode, ProjectionNode, TableScanNode},
};

#[cfg(test)]
pub mod tests;
pub struct ProofTree {
    root: Arc<dyn ProverNode>,
}

impl ProofTree {
    pub fn root(&self) -> Arc<dyn ProverNode> {
        Arc::clone(&self.root)
    }

    pub fn new(root: Arc<dyn ProverNode>) -> Self {
        Self { root }
    }


    /// Returns all descendants including root in post-order.
    pub fn sorted_nodes(&self) -> Vec<Arc<dyn ProverNode>> {
        let mut v = Vec::new();
        self.root.append_sorted_descendants(&mut v);
        v
    }

    /// Build a `ProverNode` tree from a DataFusion `LogicalPlan`.
    #[tracing::instrument(name = "from_logical_plan", skip(ctx, plan))]
    pub fn from_logical_plan(ctx: &SessionContext, plan: &LogicalPlan) -> Self {
        match plan {
            df::LogicalPlan::TableScan(_ts) => Self::new(Arc::new(
                TableScanNode::from_logical_plan(ctx, plan.clone()),
            )),
            df::LogicalPlan::Values(_vals) => todo!(),
            df::LogicalPlan::Projection(_) => Self::new(Arc::new(
                ProjectionNode::from_logical_plan(ctx, plan.clone()),
            )),
            df::LogicalPlan::Filter(_) => {
                Self::new(Arc::new(FilterNode::from_logical_plan(ctx, plan.clone())))
            },
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
}

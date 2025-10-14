use crate::proof_nodes::prover::ProverNode;
pub mod display;
use crate::proof_nodes::{
    exprs::prover::{
        ProverAggregateFunctionExprNode, ProverAliasExprNode, ProverBinaryExprNode,
        ProverColumnExprNode, ProverLiteralExprNode,
    },
    id::NodeId,
    lps::prover::{
        ProverAggregateNode, ProverFilterNode, ProverProjectionNode, ProverTableScanNode,
    },
};
use arithmetic::ctx::SharedCtx;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{
    logical_expr::{
        self, LogicalPlan, {self as df},
    },
    prelude::{Expr, SessionContext},
};
use indexmap::IndexMap;
use std::sync::Arc;
use tracing::instrument;
#[cfg(test)]
pub mod tests;

#[derive(Clone)]
pub struct ProverProofTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    ctx: SharedCtx<F, MvPCS, UvPCS>,
    root: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    proof_nodes: IndexMap<NodeId, Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
}

impl<F, MvPCS, UvPCS> ProverProofTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub fn root(&self) -> Arc<dyn ProverNode<F, MvPCS, UvPCS>> {
        Arc::clone(&self.root)
    }

    pub fn ctx(&self) -> &SharedCtx<F, MvPCS, UvPCS> {
        &self.ctx
    }

    pub fn ctx_mut(&mut self) -> &mut SharedCtx<F, MvPCS, UvPCS> {
        &mut self.ctx
    }

    pub fn root_ref(&self) -> &Arc<dyn ProverNode<F, MvPCS, UvPCS>> {
        &self.root
    }

    pub fn new(
        root: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
        ctx: SharedCtx<F, MvPCS, UvPCS>,
    ) -> Self {
        let proof_nodes = Self::sort_nodes(Arc::clone(&root), &ctx);
        Self { root, ctx, proof_nodes }
    }

    fn sort_nodes(
        root: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
        ctx: &SharedCtx<F, MvPCS, UvPCS>,
    ) -> IndexMap<NodeId, Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        todo!()
    }

    pub fn display_graphviz(&self) -> display::ProverProofTreeGraphviz<'_, F, MvPCS, UvPCS> {
        display::ProverProofTreeGraphviz::new(&self.root)
    }

    /// Returns all descendants including root in post-order.
    pub fn sorted_nodes(&self) -> Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        let mut v = Vec::new();
        self.root.append_sorted_descendants(&mut v);
        v
    }

    /// Returns a map from node identifier to the corresponding prover node.
    pub fn flatten(&self) -> IndexMap<NodeId, Arc<dyn ProverNode<F, MvPCS, UvPCS>>>
    where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>> + 'static,
        UvPCS: PCS<F, Poly = LDE<F>> + 'static,
    {
        fn collect<F, MvPCS, UvPCS>(
            node: &Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
            out: &mut IndexMap<NodeId, Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
        ) where
            F: PrimeField,
            MvPCS: PCS<F, Poly = MLE<F>> + 'static,
            UvPCS: PCS<F, Poly = LDE<F>> + 'static,
        {
            out.insert(node.node_id(), Arc::clone(node));
            for child in node.children() {
                collect(child, out);
            }
        }

        let mut map = IndexMap::new();
        collect(&self.root, &mut map);
        map
    }

    /// Build a `ProverNode` tree from a DataFusion `Expr`.
    /// This is where dispatching happens based on the type of expression.
    #[instrument(level = "debug", skip_all)]
    pub fn from_expr(
        ctx: &SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        parent_node_id: &NodeId,
    ) -> Self
    where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>> + 'static,
        UvPCS: PCS<F, Poly = LDE<F>> + 'static,
    {
        match expr.clone() {
            Expr::Alias(_) => Self::new(
                Arc::new(<ProverAliasExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::Column(_) => Self::new(
                Arc::new(
                    <ProverColumnExprNode as ProverNode<F, MvPCS, UvPCS>>::from_expr(
                        ctx,
                        prover_ctx.clone(),
                        expr,
                        parent_node_id.clone(),
                    ),
                ),
                prover_ctx,
            ),
            Expr::Literal(_) => Self::new(
                Arc::new(
                    <ProverLiteralExprNode as ProverNode<F, MvPCS, UvPCS>>::from_expr(
                        ctx,
                        prover_ctx.clone(),
                        expr,
                        parent_node_id.clone(),
                    ),
                ),
                prover_ctx,
            ),
            Expr::BinaryExpr(_) => Self::new(
                Arc::new(<ProverBinaryExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::AggregateFunction(_) => Self::new(
                Arc::new(
                    <ProverAggregateFunctionExprNode<F, MvPCS, UvPCS> as ProverNode<
                        F,
                        MvPCS,
                        UvPCS,
                    >>::from_expr(
                        ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                    ),
                ),
                prover_ctx,
            ),
            _ => todo!(),
        }
    }

    /// Build a `ProverNode` tree from a DataFusion `LogicalPlan`.
    /// This is where dispatching happens based on the type of logical plan
    /// node.
    #[instrument(level = "debug", skip_all)]
    pub fn from_lp(
        ctx: &SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        plan: &LogicalPlan,
        parent_node_id: &NodeId,
    ) -> Self {
        match plan {
            df::LogicalPlan::TableScan(_ts) => Self::new(
                Arc::new(
                    <ProverTableScanNode as ProverNode<F, MvPCS, UvPCS>>::from_lp(
                        ctx,
                        prover_ctx.clone(),
                        plan.clone(),
                        parent_node_id.clone(),
                    ),
                ),
                prover_ctx,
            ),
            df::LogicalPlan::Values(_vals) => todo!(),
            df::LogicalPlan::Projection(_) => Self::new(
                Arc::new(<ProverProjectionNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_lp(
                    ctx,
                    prover_ctx.clone(),
                    plan.clone(),
                    parent_node_id.clone(),
                )),
                prover_ctx,
            ),
            df::LogicalPlan::Filter(_) => Self::new(
                Arc::new(<ProverFilterNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_lp(
                    ctx,
                    prover_ctx.clone(),
                    plan.clone(),
                    parent_node_id.clone(),
                )),
                prover_ctx,
            ),
            df::LogicalPlan::Window(_w) => todo!(),
            df::LogicalPlan::Aggregate(_aggr) => Self::new(
                Arc::new(<ProverAggregateNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_lp(
                    ctx,
                    prover_ctx.clone(),
                    plan.clone(),
                    parent_node_id.clone(),
                )),
                prover_ctx,
            ),
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

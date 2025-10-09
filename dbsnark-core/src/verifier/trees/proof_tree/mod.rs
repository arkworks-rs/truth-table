use std::sync::Arc;

use crate::proof_nodes::{
    exprs::verifier::{
        VerifierAliasExprNode, VerifierBinaryExprNode, VerifierColumnExprNode,
        VerifierLiteralExprNode,
    },
    id::NodeId,
    lps::verifier::{VerifierFilterNode, VerifierProjectionNode, VerifierTableScanNode},
    verifier::VerifierNode,
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
use tracing::instrument;
mod display;
#[cfg(test)]
pub mod tests;
#[derive(Clone)]
pub struct VerifierProofTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    ctx: SharedCtx<F, MvPCS, UvPCS>,
    root: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
}

impl<F, MvPCS, UvPCS> VerifierProofTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub fn root(&self) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>> {
        Arc::clone(&self.root)
    }

    pub fn ctx(&self) -> &SharedCtx<F, MvPCS, UvPCS> {
        &self.ctx
    }

    pub fn ctx_mut(&mut self) -> &mut SharedCtx<F, MvPCS, UvPCS> {
        &mut self.ctx
    }

    pub fn root_ref(&self) -> &Arc<dyn VerifierNode<F, MvPCS, UvPCS>> {
        &self.root
    }

    pub fn new(
        root: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
        ctx: SharedCtx<F, MvPCS, UvPCS>,
    ) -> Self {
        Self { root, ctx }
    }

    pub fn display_graphviz(&self) -> display::VerifierProofTreeGraphviz<'_, F, MvPCS, UvPCS> {
        display::VerifierProofTreeGraphviz::new(&self.root)
    }

    /// Returns all descendants including root in post-order.
    pub fn sorted_nodes(&self) -> Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        let mut v = Vec::new();
        self.root.append_sorted_descendants(&mut v);
        v
    }

    /// Returns a map from node identifier to the corresponding verifier node.
    pub fn flatten(&self) -> IndexMap<NodeId, Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>
    where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>> + 'static,
        UvPCS: PCS<F, Poly = LDE<F>> + 'static,
    {
        fn collect<F, MvPCS, UvPCS>(
            node: &Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
            out: &mut IndexMap<NodeId, Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
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

    #[instrument(level = "debug", skip_all)]
    pub fn from_expr(
        ctx: &SessionContext,
        verifier_ctx: SharedCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        parent_logical_plan: &LogicalPlan,
    ) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>>
    where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>> + 'static,
        UvPCS: PCS<F, Poly = LDE<F>> + 'static,
    {
        match expr.clone() {
            Expr::Alias(_) => Arc::new(<VerifierAliasExprNode<F, MvPCS, UvPCS> as VerifierNode<
                F,
                MvPCS,
                UvPCS,
            >>::from_expr(
                ctx,
                verifier_ctx.clone(),
                expr,
                parent_logical_plan.clone(),
            )),
            Expr::Column(_) => {
                Arc::new(
                    <VerifierColumnExprNode as VerifierNode<F, MvPCS, UvPCS>>::from_expr(
                        ctx,
                        verifier_ctx.clone(),
                        expr,
                        parent_logical_plan.clone(),
                    ),
                )
            },
            Expr::Literal(_) => {
                Arc::new(
                    <VerifierLiteralExprNode as VerifierNode<F, MvPCS, UvPCS>>::from_expr(
                        ctx,
                        verifier_ctx.clone(),
                        expr,
                        parent_logical_plan.clone(),
                    ),
                )
            },
            Expr::BinaryExpr(_) => {
                Arc::new(<VerifierBinaryExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx, expr, parent_logical_plan.clone()
                ))
            },
            _ => todo!(),
        }
    }

    /// Build a `VerifierNode` tree from a DataFusion `LogicalPlan`.
    #[instrument(level = "debug", skip_all)]
    pub fn from_lp(
        ctx: &SessionContext,
        verifier_ctx: SharedCtx<F, MvPCS, UvPCS>,
        plan: &LogicalPlan,
    ) -> Self {
        match plan {
            df::LogicalPlan::TableScan(_ts) => Self::new(
                Arc::new(
                    <VerifierTableScanNode as VerifierNode<F, MvPCS, UvPCS>>::from_lp(
                        ctx,
                        verifier_ctx.clone(),
                        plan.clone(),
                    ),
                ),
                verifier_ctx,
            ),
            df::LogicalPlan::Values(_vals) => todo!(),
            df::LogicalPlan::Projection(_) => Self::new(
                Arc::new(<VerifierProjectionNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_lp(
                    ctx, verifier_ctx.clone(), plan.clone()
                )),
                verifier_ctx,
            ),
            df::LogicalPlan::Filter(_) => Self::new(
                Arc::new(<VerifierFilterNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_lp(
                    ctx, verifier_ctx.clone(), plan.clone()
                )),
                verifier_ctx,
            ),
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

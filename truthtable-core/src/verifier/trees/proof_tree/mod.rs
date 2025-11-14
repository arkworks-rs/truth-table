use std::sync::Arc;

use crate::proof_nodes::{
    exprs::verifier as expr_verifier,
    id::NodeId,
    lps::{
        join::VerifierJoinNode,
        sort::VerifierSortNode,
        verifier::{
            VerifierAggregateNode, VerifierFilterNode, VerifierProjectionNode,
            VerifierSubqueryAliasNode, VerifierTableScanNode,
        },
    },
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
        LogicalPlan, {self as df},
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
    arena: IndexMap<NodeId, Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
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
        let arena = Self::sort_nodes(Arc::clone(&root));
        Self { root, ctx, arena }
    }

    fn sort_nodes(
        root: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    ) -> IndexMap<NodeId, Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        fn collect<F, MvPCS, UvPCS>(
            node: &Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
            out: &mut Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
        ) where
            F: PrimeField,
            MvPCS: PCS<F, Poly = MLE<F>> + 'static,
            UvPCS: PCS<F, Poly = LDE<F>> + 'static,
        {
            for child in node.children() {
                collect(child, out);
            }
            out.push(Arc::clone(node));
        }

        let mut nodes = Vec::new();
        collect(&root, &mut nodes);

        let mut ordered_map = IndexMap::with_capacity(nodes.len());
        for node in nodes {
            ordered_map.insert(node.node_id(), node);
        }

        ordered_map
    }

    pub fn display_graphviz(&self) -> display::VerifierProofTreeGraphviz<'_, F, MvPCS, UvPCS> {
        display::VerifierProofTreeGraphviz::new(&self.root)
    }

    pub fn arena(&self) -> &IndexMap<NodeId, Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        &self.arena
    }

    pub fn node(&self, node_id: &NodeId) -> Option<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        self.arena.get(node_id)
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
        self.arena.clone()
    }

    #[instrument(level = "debug", skip_all)]
    pub fn from_expr(
        ctx: &SessionContext,
        verifier_ctx: SharedCtx<F, MvPCS, UvPCS>,
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
                Arc::new(<expr_verifier::VerifierAliasExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::Column(_) => Self::new(
                Arc::new(
                    <expr_verifier::VerifierColumnExprNode as VerifierNode<F, MvPCS, UvPCS>>::from_expr(
                        ctx,
                        verifier_ctx.clone(),
                        expr,
                        parent_node_id.clone(),
                    ),
                ),
                verifier_ctx,
            ),
            Expr::ScalarVariable(..) => Self::new(
                Arc::new(
                    <expr_verifier::VerifierScalarVariableExprNode<F, MvPCS, UvPCS> as VerifierNode<
                        F,
                        MvPCS,
                        UvPCS,
                    >>::from_expr(
                        ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                    ),
                ),
                verifier_ctx,
            ),
            Expr::Literal(_) => Self::new(
                Arc::new(
                    <expr_verifier::VerifierLiteralExprNode as VerifierNode<F, MvPCS, UvPCS>>::from_expr(
                        ctx,
                        verifier_ctx.clone(),
                        expr,
                        parent_node_id.clone(),
                    ),
                ),
                verifier_ctx,
            ),
            Expr::BinaryExpr(_) => Self::new(
                Arc::new(<expr_verifier::VerifierBinaryExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::Like(_) => Self::new(
                Arc::new(<expr_verifier::VerifierLikeExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::SimilarTo(_) => Self::new(
                Arc::new(<expr_verifier::VerifierSimilarToExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::Not(_) => Self::new(
                Arc::new(<expr_verifier::VerifierNotExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::IsNotNull(_) => Self::new(
                Arc::new(<expr_verifier::VerifierIsNotNullExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::IsNull(_) => Self::new(
                Arc::new(<expr_verifier::VerifierIsNullExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::IsTrue(_) => Self::new(
                Arc::new(<expr_verifier::VerifierIsTrueExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::IsFalse(_) => Self::new(
                Arc::new(<expr_verifier::VerifierIsFalseExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::IsUnknown(_) => Self::new(
                Arc::new(<expr_verifier::VerifierIsUnknownExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::IsNotTrue(_) => Self::new(
                Arc::new(<expr_verifier::VerifierIsNotTrueExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::IsNotFalse(_) => Self::new(
                Arc::new(<expr_verifier::VerifierIsNotFalseExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::IsNotUnknown(_) => Self::new(
                Arc::new(<expr_verifier::VerifierIsNotUnknownExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::Negative(_) => Self::new(
                Arc::new(<expr_verifier::VerifierNegativeExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::Between(_) => Self::new(
                Arc::new(<expr_verifier::VerifierBetweenExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::Case(_) => Self::new(
                Arc::new(<expr_verifier::VerifierCaseExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::Cast(_) => Self::new(
                Arc::new(<expr_verifier::VerifierCastExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::TryCast(_) => Self::new(
                Arc::new(<expr_verifier::VerifierTryCastExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::ScalarFunction(_) => Self::new(
                Arc::new(
                    <expr_verifier::VerifierScalarFunctionExprNode<F, MvPCS, UvPCS> as VerifierNode<
                        F,
                        MvPCS,
                        UvPCS,
                    >>::from_expr(
                        ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                    ),
                ),
                verifier_ctx,
            ),
            Expr::AggregateFunction(_) => Self::new(
                Arc::new(
                    <expr_verifier::VerifierAggregateFunctionExprNode<F, MvPCS, UvPCS> as VerifierNode<
                        F,
                        MvPCS,
                        UvPCS,
                    >>::from_expr(
                        ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                    ),
                ),
                verifier_ctx,
            ),
            Expr::WindowFunction(_) => Self::new(
                Arc::new(
                    <expr_verifier::VerifierWindowFunctionExprNode<F, MvPCS, UvPCS> as VerifierNode<
                        F,
                        MvPCS,
                        UvPCS,
                    >>::from_expr(
                        ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                    ),
                ),
                verifier_ctx,
            ),
            Expr::InList(_) => Self::new(
                Arc::new(<expr_verifier::VerifierInListExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::Exists(_) => Self::new(
                Arc::new(<expr_verifier::VerifierExistsExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::InSubquery(_) => Self::new(
                Arc::new(<expr_verifier::VerifierInSubqueryExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::ScalarSubquery(_) => Self::new(
                Arc::new(
                    <expr_verifier::VerifierScalarSubqueryExprNode<F, MvPCS, UvPCS> as VerifierNode<
                        F,
                        MvPCS,
                        UvPCS,
                    >>::from_expr(
                        ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                    ),
                ),
                verifier_ctx,
            ),
            Expr::GroupingSet(_) => Self::new(
                Arc::new(<expr_verifier::VerifierGroupingSetExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::Placeholder(_) => Self::new(
                Arc::new(<expr_verifier::VerifierPlaceholderExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            Expr::OuterReferenceColumn(..) => Self::new(
                Arc::new(
                    <expr_verifier::VerifierOuterReferenceColumnExprNode<F, MvPCS, UvPCS>
                        as VerifierNode<F, MvPCS, UvPCS>>::from_expr(
                        ctx,
                        verifier_ctx.clone(),
                        expr,
                        parent_node_id.clone(),
                    ),
                ),
                verifier_ctx,
            ),
            Expr::Unnest(_) => Self::new(
                Arc::new(<expr_verifier::VerifierUnnestExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, verifier_ctx.clone(), expr, parent_node_id.clone()
                )),
                verifier_ctx,
            ),
            _ => panic!(),
        }
    }

    /// Build a `VerifierNode` tree from a DataFusion `LogicalPlan`.
    #[instrument(level = "debug", skip_all)]
    pub fn from_lp(
        ctx: &SessionContext,
        verifier_ctx: SharedCtx<F, MvPCS, UvPCS>,
        plan: &LogicalPlan,
        parent_node_id: &NodeId,
    ) -> Self {
        match plan {
            df::LogicalPlan::TableScan(_ts) => Self::new(
                Arc::new(
                    <VerifierTableScanNode as VerifierNode<F, MvPCS, UvPCS>>::from_lp(
                        ctx,
                        verifier_ctx.clone(),
                        plan.clone(),
                        parent_node_id.clone(),
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
                    ctx,
                    verifier_ctx.clone(),
                    plan.clone(),
                    parent_node_id.clone(),
                )),
                verifier_ctx,
            ),
            df::LogicalPlan::Filter(_) => Self::new(
                Arc::new(<VerifierFilterNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_lp(
                    ctx,
                    verifier_ctx.clone(),
                    plan.clone(),
                    parent_node_id.clone(),
                )),
                verifier_ctx,
            ),
            df::LogicalPlan::Aggregate(_aggr) => Self::new(
                Arc::new(<VerifierAggregateNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_lp(
                    ctx,
                    verifier_ctx.clone(),
                    plan.clone(),
                    parent_node_id.clone(),
                )),
                verifier_ctx,
            ),
            df::LogicalPlan::Window(_w) => todo!(),
            df::LogicalPlan::Sort(_s) => Self::new(
                Arc::new(<VerifierSortNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_lp(
                    ctx,
                    verifier_ctx.clone(),
                    plan.clone(),
                    parent_node_id.clone(),
                )),
                verifier_ctx,
            ),
            df::LogicalPlan::Repartition(_r) => todo!(),
            df::LogicalPlan::Analyze(_a) => todo!(),
            df::LogicalPlan::Distinct(_d) => todo!(),
            df::LogicalPlan::Subquery(_sq) => todo!(),
            df::LogicalPlan::SubqueryAlias(_) => {
                Self::new(
                    Arc::new(
                        <VerifierSubqueryAliasNode<F, MvPCS, UvPCS> as VerifierNode<
                            F,
                            MvPCS,
                            UvPCS,
                        >>::from_lp(
                            ctx,
                            verifier_ctx.clone(),
                            plan.clone(),
                            parent_node_id.clone(),
                        ),
                    ),
                    verifier_ctx,
                )
            }
            df::LogicalPlan::Union(_) => todo!(),
            df::LogicalPlan::Extension(_ext) => todo!(),
            df::LogicalPlan::Join(_) => Self::new(
                Arc::new(<VerifierJoinNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_lp(
                    ctx,
                    verifier_ctx.clone(),
                    plan.clone(),
                    parent_node_id.clone(),
                )),
                verifier_ctx,
            ),
            df::LogicalPlan::Limit(_) => Self::new(
                Arc::new(<VerifierJoinNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_lp(
                    ctx,
                    verifier_ctx.clone(),
                    plan.clone(),
                    parent_node_id.clone(),
                )),
                verifier_ctx,
            ),
            _ => panic!(),
        }
    }
}

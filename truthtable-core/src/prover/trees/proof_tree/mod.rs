use crate::proof_nodes::prover::ProverNode;
pub mod display;
use crate::proof_nodes::{
    exprs::prover::{
        ProverAggregateFunctionExprNode, ProverAliasExprNode, ProverBetweenExprNode,
        ProverBinaryExprNode, ProverCaseExprNode, ProverCastExprNode, ProverColumnExprNode,
        ProverExistsExprNode, ProverGroupingSetExprNode, ProverInListExprNode,
        ProverInSubqueryExprNode, ProverIsFalseExprNode, ProverIsNotFalseExprNode,
        ProverIsNotNullExprNode, ProverIsNotTrueExprNode, ProverIsNotUnknownExprNode,
        ProverIsNullExprNode, ProverIsTrueExprNode, ProverIsUnknownExprNode, ProverLikeExprNode,
        ProverLiteralExprNode, ProverNegativeExprNode, ProverNotExprNode,
        ProverOuterReferenceColumnExprNode, ProverPlaceholderExprNode,
        ProverScalarFunctionExprNode, ProverScalarSubqueryExprNode, ProverScalarVariableExprNode,
        ProverSimilarToExprNode, ProverTryCastExprNode, ProverUnnestExprNode,
        ProverWildcardExprNode, ProverWindowFunctionExprNode,
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
        LogicalPlan, {self as df},
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
    arena: IndexMap<NodeId, Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
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
        let arena = Self::sort_nodes(Arc::clone(&root));
        Self { ctx, root, arena }
    }

    fn sort_nodes(
        root: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    ) -> IndexMap<NodeId, Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        fn collect<F, MvPCS, UvPCS>(
            node: &Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
            out: &mut Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
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

    pub fn display_graphviz(&self) -> display::ProverProofTreeGraphviz<'_, F, MvPCS, UvPCS> {
        display::ProverProofTreeGraphviz::new(&self.root)
    }

    pub fn arena(&self) -> &IndexMap<NodeId, Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        &self.arena
    }

    pub fn node(&self, node_id: &NodeId) -> Option<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        self.arena.get(node_id)
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
        self.arena.clone()
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
            Expr::ScalarVariable(..) => Self::new(
                Arc::new(
                    <ProverScalarVariableExprNode<F, MvPCS, UvPCS> as ProverNode<
                        F,
                        MvPCS,
                        UvPCS,
                    >>::from_expr(
                        ctx, prover_ctx.clone(), expr, parent_node_id.clone()
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
            Expr::Like(_) => Self::new(
                Arc::new(<ProverLikeExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::SimilarTo(_) => Self::new(
                Arc::new(<ProverSimilarToExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::Not(_) => Self::new(
                Arc::new(<ProverNotExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::IsNotNull(_) => Self::new(
                Arc::new(<ProverIsNotNullExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::IsNull(_) => Self::new(
                Arc::new(<ProverIsNullExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::IsTrue(_) => Self::new(
                Arc::new(<ProverIsTrueExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::IsFalse(_) => Self::new(
                Arc::new(<ProverIsFalseExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::IsUnknown(_) => Self::new(
                Arc::new(<ProverIsUnknownExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::IsNotTrue(_) => Self::new(
                Arc::new(<ProverIsNotTrueExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::IsNotFalse(_) => Self::new(
                Arc::new(<ProverIsNotFalseExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::IsNotUnknown(_) => {
                Self::new(
                    Arc::new(
                        <ProverIsNotUnknownExprNode<F, MvPCS, UvPCS> as ProverNode<
                            F,
                            MvPCS,
                            UvPCS,
                        >>::from_expr(
                            ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                        ),
                    ),
                    prover_ctx,
                )
            },
            Expr::Negative(_) => Self::new(
                Arc::new(<ProverNegativeExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::Between(_) => Self::new(
                Arc::new(<ProverBetweenExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::Case(_) => Self::new(
                Arc::new(<ProverCaseExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::Cast(_) => Self::new(
                Arc::new(<ProverCastExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::TryCast(_) => Self::new(
                Arc::new(<ProverTryCastExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::ScalarFunction(_) => Self::new(
                Arc::new(
                    <ProverScalarFunctionExprNode<F, MvPCS, UvPCS> as ProverNode<
                        F,
                        MvPCS,
                        UvPCS,
                    >>::from_expr(
                        ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                    ),
                ),
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
            Expr::WindowFunction(_) => Self::new(
                Arc::new(
                    <ProverWindowFunctionExprNode<F, MvPCS, UvPCS> as ProverNode<
                        F,
                        MvPCS,
                        UvPCS,
                    >>::from_expr(
                        ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                    ),
                ),
                prover_ctx,
            ),
            Expr::InList(_) => Self::new(
                Arc::new(<ProverInListExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::Exists(_) => Self::new(
                Arc::new(<ProverExistsExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::InSubquery(_) => Self::new(
                Arc::new(<ProverInSubqueryExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::ScalarSubquery(_) => Self::new(
                Arc::new(
                    <ProverScalarSubqueryExprNode<F, MvPCS, UvPCS> as ProverNode<
                        F,
                        MvPCS,
                        UvPCS,
                    >>::from_expr(
                        ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                    ),
                ),
                prover_ctx,
            ),

            Expr::GroupingSet(_) => Self::new(
                Arc::new(<ProverGroupingSetExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::Placeholder(_) => Self::new(
                Arc::new(<ProverPlaceholderExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            Expr::OuterReferenceColumn(..) => Self::new(
                Arc::new(
                    <ProverOuterReferenceColumnExprNode<F, MvPCS, UvPCS> as ProverNode<
                        F,
                        MvPCS,
                        UvPCS,
                    >>::from_expr(
                        ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                    ),
                ),
                prover_ctx,
            ),
            Expr::Unnest(_) => Self::new(
                Arc::new(<ProverUnnestExprNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx, prover_ctx.clone(), expr, parent_node_id.clone()
                )),
                prover_ctx,
            ),
            _ => panic!(),
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
            df::LogicalPlan::Sort(_s) => Self::new(
                Arc::new(<crate::proof_nodes::lps::sort::ProverSortNode<
                    F,
                    MvPCS,
                    UvPCS,
                > as ProverNode<F, MvPCS, UvPCS>>::from_lp(
                    ctx,
                    prover_ctx.clone(),
                    plan.clone(),
                    parent_node_id.clone(),
                )),
                prover_ctx,
            ),
            df::LogicalPlan::Repartition(_r) => todo!(),
            df::LogicalPlan::Analyze(_a) => todo!(),
            df::LogicalPlan::Distinct(_d) => todo!(),
            df::LogicalPlan::Subquery(_sq) => todo!(),
            df::LogicalPlan::SubqueryAlias(_sqa) => Self::new(
                Arc::new(
                    <crate::proof_nodes::lps::subquery_alias::ProverSubqueryAliasNode<
                        F,
                        MvPCS,
                        UvPCS,
                    > as ProverNode<F, MvPCS, UvPCS>>::from_lp(
                        ctx,
                        prover_ctx.clone(),
                        plan.clone(),
                        parent_node_id.clone(),
                    ),
                ),
                prover_ctx,
            ),
            df::LogicalPlan::Union(_u) => todo!(),
            df::LogicalPlan::Extension(_ext) => todo!(),
            df::LogicalPlan::Join(_j) => Self::new(
                Arc::new(<crate::proof_nodes::lps::join::ProverJoinNode<
                    F,
                    MvPCS,
                    UvPCS,
                > as ProverNode<F, MvPCS, UvPCS>>::from_lp(
                    ctx,
                    prover_ctx.clone(),
                    plan.clone(),
                    parent_node_id.clone(),
                )),
                prover_ctx,
            ),
            df::LogicalPlan::Limit(_) => Self::new(
                Arc::new(<crate::proof_nodes::lps::limit::ProverLimitNode<
                    F,
                    MvPCS,
                    UvPCS,
                > as ProverNode<F, MvPCS, UvPCS>>::from_lp(
                    ctx,
                    prover_ctx.clone(),
                    plan.clone(),
                    parent_node_id.clone(),
                )),
                prover_ctx,
            ),
            _ => panic!(),
        }
    }
}

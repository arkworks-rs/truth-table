use crate::id::NodeId;
pub mod display;
pub mod nodes;
use std::{collections::HashMap, sync::Arc};

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

use self::nodes::{
    ProverNode,
    exprs::{AliasExprNode, BinaryExprNode, ColumnExprNode, LiteralExprNode},
    lps::{FilterNode, ProjectionNode, TableScanNode},
};

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
        Self { root, ctx }
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
    pub fn flatten(&self) -> HashMap<NodeId, Arc<dyn ProverNode<F, MvPCS, UvPCS>>>
    where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>> + 'static,
        UvPCS: PCS<F, Poly = LDE<F>> + 'static,
    {
        fn collect<F, MvPCS, UvPCS>(
            node: &Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
            out: &mut HashMap<NodeId, Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
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

        let mut map = HashMap::new();
        collect(&self.root, &mut map);
        map
    }

    pub fn from_expr(
        ctx: &SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        parent_logical_plan: &LogicalPlan,
    ) -> Arc<dyn ProverNode<F, MvPCS, UvPCS>>
    where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>> + 'static,
        UvPCS: PCS<F, Poly = LDE<F>> + 'static,
    {
        match expr.clone() {
            Expr::Alias(_) => Arc::new(<AliasExprNode<F, MvPCS, UvPCS> as ProverNode<
                F,
                MvPCS,
                UvPCS,
            >>::from_expr(
                ctx,
                prover_ctx.clone(),
                expr,
                parent_logical_plan.clone(),
            )),
            Expr::Column(_) => {
                Arc::new(<ColumnExprNode as ProverNode<F, MvPCS, UvPCS>>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    expr,
                    parent_logical_plan.clone(),
                ))
            },
            Expr::Literal(_) => {
                Arc::new(<LiteralExprNode as ProverNode<F, MvPCS, UvPCS>>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    expr,
                    parent_logical_plan.clone(),
                ))
            },
            Expr::BinaryExpr(_) => Arc::new(<BinaryExprNode<F, MvPCS, UvPCS> as ProverNode<
                F,
                MvPCS,
                UvPCS,
            >>::from_expr(
                ctx, prover_ctx, expr, parent_logical_plan.clone()
            )),
            _ => todo!(),
        }
    }

    /// Build a `ProverNode` tree from a DataFusion `LogicalPlan`.
    #[tracing::instrument(name = "from_lp", skip_all)]
    pub fn from_lp(
        ctx: &SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        plan: &LogicalPlan,
    ) -> Self {
        match plan {
            df::LogicalPlan::TableScan(_ts) => Self::new(
                Arc::new(<TableScanNode as ProverNode<F, MvPCS, UvPCS>>::from_lp(
                    ctx,
                    prover_ctx.clone(),
                    plan.clone(),
                )),
                prover_ctx,
            ),
            df::LogicalPlan::Values(_vals) => todo!(),
            df::LogicalPlan::Projection(_) => Self::new(
                Arc::new(<ProjectionNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_lp(
                    ctx, prover_ctx.clone(), plan.clone()
                )),
                prover_ctx,
            ),
            df::LogicalPlan::Filter(_) => Self::new(
                Arc::new(<FilterNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_lp(
                    ctx, prover_ctx.clone(), plan.clone()
                )),
                prover_ctx,
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

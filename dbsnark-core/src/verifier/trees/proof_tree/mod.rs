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
    proof_nodes: IndexMap<NodeId, Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
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
        let proof_nodes = Self::sort_nodes(Arc::clone(&root));
        Self {
            root,
            ctx,
            proof_nodes,
        }
    }

    fn sort_nodes(
        root: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    ) -> IndexMap<NodeId, Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        fn node_ptr_id<F, MvPCS, UvPCS>(node: &Arc<dyn VerifierNode<F, MvPCS, UvPCS>>) -> usize
        where
            F: PrimeField,
            MvPCS: PCS<F, Poly = MLE<F>> + 'static,
            UvPCS: PCS<F, Poly = LDE<F>> + 'static,
        {
            let data_ptr = &**node as *const dyn VerifierNode<F, MvPCS, UvPCS> as *const ();
            data_ptr as usize
        }

        fn collect<F, MvPCS, UvPCS>(
            node: &Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
            depth: usize,
            depths: &mut IndexMap<usize, usize>,
            out: &mut Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
        ) where
            F: PrimeField,
            MvPCS: PCS<F, Poly = MLE<F>> + 'static,
            UvPCS: PCS<F, Poly = LDE<F>> + 'static,
        {
            for child in node.children() {
                collect(child, depth + 1, depths, out);
            }
            depths.insert(node_ptr_id(node), depth);
            out.push(Arc::clone(node));
        }

        let mut nodes = Vec::new();
        let mut depths = IndexMap::new();
        collect(&root, 0, &mut depths, &mut nodes);

        let mut table_scan_nodes: Vec<_> = nodes
            .iter()
            .filter(|node| {
                node.as_any()
                    .downcast_ref::<VerifierTableScanNode>()
                    .is_some()
            })
            .cloned()
            .collect();
        let mut other_nodes: Vec<_> = nodes
            .iter()
            .filter(|node| {
                node.as_any()
                    .downcast_ref::<VerifierTableScanNode>()
                    .is_none()
            })
            .cloned()
            .collect();

        let cmp_nodes = |a: &Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
                         b: &Arc<dyn VerifierNode<F, MvPCS, UvPCS>>| {
            let depth_a = depths.get(&node_ptr_id(a)).copied().unwrap_or(0);
            let depth_b = depths.get(&node_ptr_id(b)).copied().unwrap_or(0);
            depth_b
                .cmp(&depth_a)
                .then_with(|| a.node_id().to_string().cmp(&b.node_id().to_string()))
        };

        table_scan_nodes.sort_by(cmp_nodes);
        other_nodes.sort_by(cmp_nodes);

        let ordered_nodes = table_scan_nodes.into_iter().chain(other_nodes.into_iter());

        let mut ordered_map = IndexMap::with_capacity(nodes.len());
        for node in ordered_nodes {
            ordered_map.insert(node.node_id(), node);
        }

        ordered_map
    }

    pub fn display_graphviz(&self) -> display::VerifierProofTreeGraphviz<'_, F, MvPCS, UvPCS> {
        display::VerifierProofTreeGraphviz::new(&self.root)
    }

    pub fn proof_nodes(&self) -> &IndexMap<NodeId, Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        &self.proof_nodes
    }

    pub fn node(&self, node_id: &NodeId) -> Option<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        self.proof_nodes.get(node_id)
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
        self.proof_nodes.clone()
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
                Arc::new(<VerifierAliasExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx,
                    verifier_ctx.clone(),
                    expr,
                    parent_node_id.clone(),
                )),
                verifier_ctx,
            ),
            Expr::Column(_) => Self::new(
                Arc::new(
                    <VerifierColumnExprNode as VerifierNode<F, MvPCS, UvPCS>>::from_expr(
                        ctx,
                        verifier_ctx.clone(),
                        expr,
                        parent_node_id.clone(),
                    ),
                ),
                verifier_ctx,
            ),
            Expr::Literal(_) => Self::new(
                Arc::new(
                    <VerifierLiteralExprNode as VerifierNode<F, MvPCS, UvPCS>>::from_expr(
                        ctx,
                        verifier_ctx.clone(),
                        expr,
                        parent_node_id.clone(),
                    ),
                ),
                verifier_ctx,
            ),
            Expr::BinaryExpr(_) => Self::new(
                Arc::new(<VerifierBinaryExprNode<F, MvPCS, UvPCS> as VerifierNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_expr(
                    ctx,
                    verifier_ctx.clone(),
                    expr,
                    parent_node_id.clone(),
                )),
                verifier_ctx,
            ),
            _ => todo!(),
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

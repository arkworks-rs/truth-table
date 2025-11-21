use crate::{
    proof_nodes::{
        exprs::{
            binary_expr::ProverBinaryExprNode, column::ProverColumnExprNode,
            literal::ProverLiteralExprNode,
        },
        lps::{
            filter::ProverFilterNode, projection::ProverProjectionNode,
            table_scan::ProverTableScanNode,
        },
        prover::{ProverExprNode, ProverLpNode, ProverPlanNode},
    },
    tree::{NodeId, ProverPlanTree},
};
pub mod display;
use arithmetic::ctx::SharedCtx;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{
    logical_expr::LogicalPlan,
    prelude::{Expr, SessionContext},
};
use indexmap::IndexMap;
use std::{fmt, sync::Arc};
use tracing::instrument;
#[cfg(test)]
pub mod tests;

#[derive(Clone)]
pub struct ProverProofTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    ctx: SharedCtx<F, MvPCS, UvPCS>,
    root: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    arena: IndexMap<NodeId, Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>>,
}

impl<F, MvPCS, UvPCS> fmt::Debug for ProverProofTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_graphviz())
    }
}

impl<F, MvPCS, UvPCS> fmt::Display for ProverProofTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let node_count = self.arena.len();
        let root_label = self.root.name();
        write!(
            f,
            "ProverProofTree {{ nodes: {}, root: {} }}",
            node_count, root_label
        )
    }
}

impl<F, MvPCS, UvPCS> ProverPlanTree<F, MvPCS, UvPCS> for ProverProofTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn arena(&self) -> &IndexMap<NodeId, Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>> {
        &self.arena
    }

    fn root(&self) -> &Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>> {
        &self.root
    }

    fn get_node(&self, node_id: &NodeId) -> Option<&Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>> {
        self.arena.get(node_id)
    }
}

impl<F, MvPCS, UvPCS> ProverProofTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    pub fn ctx(&self) -> &SharedCtx<F, MvPCS, UvPCS> {
        &self.ctx
    }

    pub fn ctx_mut(&mut self) -> &mut SharedCtx<F, MvPCS, UvPCS> {
        &mut self.ctx
    }

    pub fn new(
        root: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
        ctx: SharedCtx<F, MvPCS, UvPCS>,
    ) -> Self {
        let arena = build_arena::<F, MvPCS, UvPCS>(&root);
        Self { ctx, root, arena }
    }

    // pub fn display_graphviz(&self) -> display::ProverProofTreeGraphviz<'_, F, MvPCS, UvPCS> {
    //     display::ProverProofTreeGraphviz::new(&self.root)
    // }

    pub fn arena(&self) -> &IndexMap<NodeId, Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>> {
        &self.arena
    }

    /// Returns a map from node identifier to the corresponding prover node.
    pub fn flatten(&self) -> IndexMap<NodeId, Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>>
    where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>> + 'static,
        UvPCS: PCS<F, Poly = LDE<F>> + 'static,
    {
        self.arena.clone()
    }

    /// Build a `ProverPlanNode` tree from a DataFusion `Expr`.
    /// This is where dispatching happens based on the type of expression.
    #[instrument(level = "debug", skip_all)]
    pub fn from_expr(
        ctx: &SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        parent_node_id: &Option<NodeId>,
    ) -> Self
    where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>> + 'static,
        UvPCS: PCS<F, Poly = LDE<F>> + 'static,
    {
        match expr.clone() {
            Expr::Column(_) => Self::new(
                Arc::new(ProverColumnExprNode::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    expr.clone(),
                    parent_node_id
                        .as_ref()
                        .cloned()
                        .unwrap_or(NodeId::Expr(expr.clone())),
                )),
                prover_ctx,
            ),
            Expr::Literal(_) => Self::new(
                Arc::new(ProverLiteralExprNode::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    expr.clone(),
                    parent_node_id
                        .as_ref()
                        .cloned()
                        .unwrap_or(NodeId::Expr(expr.clone())),
                )),
                prover_ctx,
            ),
            Expr::BinaryExpr(_) => Self::new(
                Arc::new(ProverBinaryExprNode::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    expr.clone(),
                    parent_node_id
                        .as_ref()
                        .cloned()
                        .unwrap_or(NodeId::Expr(expr.clone())),
                )),
                prover_ctx,
            ),
            _ => panic!("unsupported expression node for prover proof tree"),
        }
    }

    /// Build a `ProverPlanNode` tree from a DataFusion `LogicalPlan`.
    /// This is where dispatching happens based on the type of logical plan
    /// node.
    #[instrument(level = "debug", skip_all)]
    pub fn from_lp(
        ctx: &SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        plan: &LogicalPlan,
        parent_node_id: &Option<NodeId>,
    ) -> Self {
        match plan {
            LogicalPlan::Projection(_) => Self::new(
                Arc::new(ProverProjectionNode::from_lp(
                    ctx,
                    prover_ctx.clone(),
                    plan.clone(),
                    parent_node_id
                        .as_ref()
                        .cloned()
                        .unwrap_or(NodeId::LP(plan.clone())),
                )),
                prover_ctx,
            ),
            LogicalPlan::TableScan(_) => Self::new(
                Arc::new(ProverTableScanNode::from_lp(
                    ctx,
                    prover_ctx.clone(),
                    plan.clone(),
                    parent_node_id
                        .as_ref()
                        .cloned()
                        .unwrap_or(NodeId::LP(plan.clone())),
                )),
                prover_ctx,
            ),

            LogicalPlan::Filter(_) => Self::new(
                Arc::new(ProverFilterNode::from_lp(
                    ctx,
                    prover_ctx.clone(),
                    plan.clone(),
                    parent_node_id
                        .as_ref()
                        .cloned()
                        .unwrap_or(NodeId::LP(plan.clone())),
                )),
                prover_ctx,
            ),
            _ => panic!("unsupported logical plan node for prover proof tree"),
        }
    }
}

fn build_arena<F, MvPCS, UvPCS>(
    root: &Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
) -> IndexMap<NodeId, Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn dfs<F, MvPCS, UvPCS>(
        node: &Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
        out: &mut Vec<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>>,
    ) where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
        UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
    {
        for child in node.plan_children() {
            dfs(&child, out);
        }
        out.push(Arc::clone(node));
    }

    let mut nodes = Vec::new();
    dfs(root, &mut nodes);

    nodes.into_iter().fold(IndexMap::new(), |mut acc, node| {
        acc.insert(node.node_id(), node);
        acc
    })
}

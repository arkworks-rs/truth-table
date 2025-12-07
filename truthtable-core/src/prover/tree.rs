use crate::{
    proof_nodes::{
        exprs::{
            aggregate_function::ProverAggregateFunctionExprNode, alias::ProverAliasExprNode,
            binary_expr::ProverBinaryExprNode, column::ProverColumnExprNode,
            literal::ProverLiteralExprNode,
        },
        lps::{
            aggregate::ProverAggregateNode, filter::ProverFilterNode,
            projection::ProverProjectionNode, sort::ProverSortNode,
            table_scan::ProverTableScanNode,
        },
        prover::{ProverExprNode, ProverLpNode, ProverPlanNode},
    },
    tree::{NodeId, ProverPlanTree},
};
use arithmetic::ctx::CtxOracles;
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
pub struct ProverProofTree<B>
where
B:SnarkBackend
{
    ctx: CtxOracles<B>,
    root: Arc<dyn ProverPlanNode<B>>,
    arena: IndexMap<NodeId, Arc<dyn ProverPlanNode<B>>>,
}

impl<B> fmt::Debug for ProverProofTree<B>
where
B:SnarkBackend
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_graphviz(false))
    }
}

impl<B> fmt::Display for ProverProofTree<B>
where
B:SnarkBackend
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

impl<B> ProverPlanTree<B> for ProverProofTree<B>
where
B:SnarkBackend
{
    type Node = dyn ProverPlanNode<B>;
    fn arena(&self) -> &IndexMap<NodeId, Arc<Self::Node>> {
        &self.arena
    }

    fn root(&self) -> &Arc<Self::Node> {
        &self.root
    }

    fn get_node(&self, node_id: &NodeId) -> Option<&Arc<Self::Node>> {
        self.arena.get(node_id)
    }
}

impl<B> ProverProofTree<B>
where
B:SnarkBackend
{
    pub fn ctx(&self) -> &CtxOracles<B> {
        &self.ctx
    }

    pub fn ctx_mut(&mut self) -> &mut CtxOracles<B> {
        &mut self.ctx
    }

    pub fn new(
        root: Arc<dyn ProverPlanNode<B>>,
        ctx: CtxOracles<B>,
    ) -> Self {
        let arena = build_arena::<B>(&root);
        Self { ctx, root, arena }
    }

    pub fn arena(&self) -> &IndexMap<NodeId, Arc<dyn ProverPlanNode<B>>> {
        &self.arena
    }

    /// Returns a map from node identifier to the corresponding prover node.
    pub fn flatten(&self) -> IndexMap<NodeId, Arc<dyn ProverPlanNode<B>>>
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
        prover_ctx: CtxOracles<B>,
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
            Expr::AggregateFunction(_) => Self::new(
                Arc::new(ProverAggregateFunctionExprNode::from_expr(
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
            Expr::Alias(_) => Self::new(
                Arc::new(ProverAliasExprNode::from_expr(
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
            _ => panic!(
                "unsupported expression node for prover proof tree: {}",
                expr
            ),
        }
    }

    /// Build a `ProverPlanNode` tree from a DataFusion `LogicalPlan`.
    /// This is where dispatching happens based on the type of logical plan
    /// node.
    #[instrument(level = "debug", skip_all)]
    pub fn from_lp(
        ctx: &SessionContext,
        prover_ctx: CtxOracles<B>,
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
            LogicalPlan::Aggregate(_) => Self::new(
                Arc::new(ProverAggregateNode::from_lp(
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
            LogicalPlan::Sort(_) => Self::new(
                Arc::new(ProverSortNode::from_lp(
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

fn build_arena<B>(
    root: &Arc<dyn ProverPlanNode<B>>,
) -> IndexMap<NodeId, Arc<dyn ProverPlanNode<B>>>
where
B:SnarkBackend
{
    fn dfs<B>(
        node: &Arc<dyn ProverPlanNode<B>>,
        out: &mut Vec<Arc<dyn ProverPlanNode<B>>>,
    ) where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
        UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
    {
        for child in node.children() {
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

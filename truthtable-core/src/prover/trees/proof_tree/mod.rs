use crate::{
    proof_nodes::prover::ProverPlanNode,
    tree::{NodeId, Tree},
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
use std::sync::Arc;
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

impl<F, MvPCS, UvPCS> Tree<F, MvPCS, UvPCS> for ProverProofTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    type NodeType = dyn ProverPlanNode<F, MvPCS, UvPCS>;

    fn arena(&self) -> &IndexMap<NodeId, Arc<Self::NodeType>> {
        &self.arena
    }

    fn root(&self) -> &Arc<Self::NodeType> {
        &self.root
    }

    fn get_node(&self, node_id: &NodeId) -> Option<&Arc<Self::NodeType>> {
        self.arena.get(node_id)
    }
    fn display(&self) -> String {
        todo!()
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
        let arena = Self::sort_nodes(Arc::clone(&root));
        Self { ctx, root, arena }
    }

    fn sort_nodes(
        root: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    ) -> IndexMap<NodeId, Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>> {
        fn collect<F, MvPCS, UvPCS>(
            node: &Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
            out: &mut Vec<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>>,
        ) where
            F: PrimeField,
            MvPCS: PCS<F, Poly = MLE<F>> + 'static,
            UvPCS: PCS<F, Poly = LDE<F>> + 'static,
        {
            // for child in node.children() {
            //     collect(child, out);
            // }
            todo!();
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
        parent_node_id: &NodeId,
    ) -> Self
    where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>> + 'static,
        UvPCS: PCS<F, Poly = LDE<F>> + 'static,
    {
        match expr.clone() {
            _ => panic!(),
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
        parent_node_id: &NodeId,
    ) -> Self {
        match plan {
            _ => panic!(),
        }
    }
}

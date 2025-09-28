pub mod display;
pub mod nodes;

use std::{collections::HashMap, sync::Arc};

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

use crate::proof_tree::nodes::ProverNodeNodeId;

use self::nodes::{
    ProverNode,
    lps::{FilterNode, ProjectionNode, TableScanNode},
};

#[cfg(test)]
pub mod tests;

#[derive(Clone)]
pub struct ProofTree<F, MvPCS, UvPCS> {
    root: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
}

impl<F, MvPCS, UvPCS> ProofTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub fn root(&self) -> Arc<dyn ProverNode<F, MvPCS, UvPCS>> {
        Arc::clone(&self.root)
    }

    pub fn root_ref(&self) -> &Arc<dyn ProverNode<F, MvPCS, UvPCS>> {
        &self.root
    }

    pub fn new(root: Arc<dyn ProverNode<F, MvPCS, UvPCS>>) -> Self {
        Self { root }
    }

    pub fn display_graphviz(&self) -> display::ProofTreeGraphviz<'_, F, MvPCS, UvPCS> {
        display::ProofTreeGraphviz::new(&self.root)
    }

    /// Returns all descendants including root in post-order.
    pub fn sorted_nodes(&self) -> Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        let mut v = Vec::new();
        self.root.append_sorted_descendants(&mut v);
        v
    }

    /// Returns a map from node identifier to the corresponding prover node.
    pub fn flatten(&self) -> HashMap<ProverNodeNodeId, Arc<dyn ProverNode<F, MvPCS, UvPCS>>>
    where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>> + 'static,
        UvPCS: PCS<F, Poly = LDE<F>> + 'static,
    {
        fn collect<F, MvPCS, UvPCS>(
            node: &Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
            out: &mut HashMap<ProverNodeNodeId, Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
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

    /// Build a `ProverNode` tree from a DataFusion `LogicalPlan`.
    #[tracing::instrument(name = "from_logical_plan", skip(ctx, plan))]
    pub fn from_logical_plan(ctx: &SessionContext, plan: &LogicalPlan) -> Self {
        match plan {
            df::LogicalPlan::TableScan(_ts) => Self::new(Arc::new(<TableScanNode as ProverNode<
                F,
                MvPCS,
                UvPCS,
            >>::from_logical_plan(
                ctx, plan.clone()
            ))),
            df::LogicalPlan::Values(_vals) => todo!(),
            df::LogicalPlan::Projection(_) => {
                Self::new(Arc::new(<ProjectionNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_logical_plan(
                    ctx, plan.clone()
                )))
            },
            df::LogicalPlan::Filter(_) => {
                Self::new(Arc::new(<FilterNode<F, MvPCS, UvPCS> as ProverNode<
                    F,
                    MvPCS,
                    UvPCS,
                >>::from_logical_plan(
                    ctx, plan.clone()
                )))
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

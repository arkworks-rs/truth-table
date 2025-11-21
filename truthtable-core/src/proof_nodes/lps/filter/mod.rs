use std::sync::Arc;

use arithmetic::ctx::SharedCtx;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    prover::ArgProver,
};
use datafusion::{arrow::datatypes::SchemaRef, prelude::SessionContext};
use datafusion_common::Statistics;
use datafusion_expr::{Expr, Filter, LogicalPlan};
use rayon::vec;

use crate::{
    proof_nodes::{
        HintDF,
        cost::ProvingCost,
        prover::{ProverLpNode, ProverPlanNode},
    },
    prover::trees::proof_tree::ProverProofTree,
    tree::{Node, NodeId, Tree},
};

/// The implementation of a filter node in the prover proof tree.
pub struct ProverFilterNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    // The filter information from DataFusion
    filter: Filter,
    // The prover plan children nodes for the Filter expressions
    input: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    // The prover predicate expression node for the filter condition
    predicate: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
}

impl<F, MvPCS, UvPCS> Node<F, MvPCS, UvPCS> for ProverFilterNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn children(&self) -> Vec<Arc<dyn Node<F, MvPCS, UvPCS>>> {
        vec![
            self.input.clone() as Arc<dyn Node<F, MvPCS, UvPCS>>,
            self.predicate.clone() as Arc<dyn Node<F, MvPCS, UvPCS>>,
        ]
    }

    fn node_id(&self) -> NodeId {
        NodeId::LP(LogicalPlan::Filter(self.filter.clone()))
    }
}

impl<F, MvPCS, UvPCS> ProverPlanNode<F, MvPCS, UvPCS> for ProverFilterNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn output(&self, _proof_tree: &ProverProofTree<F, MvPCS, UvPCS>) -> HintDF {
        todo!()
    }

    fn hint_dfs(
        &self,
        _proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> indexmap::IndexMap<String, HintDF> {
        todo!()
    }

    fn ctx_lp_node(
        &self,
        proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>> {
        todo!()
    }

    fn arithmetic_post_process(&self) {
        todo!()
    }

    fn add_virtual_witness(&self, prover: &mut ArgProver<F, MvPCS, UvPCS>) {
        todo!()
    }

    fn prove_piop(
        &self,
        _prover: &mut ArgProver<F, MvPCS, UvPCS>,
    ) -> ark_piop::errors::SnarkResult<()> {
        todo!()
    }

    fn cost(&self, statistics: Statistics, schema: SchemaRef) -> ProvingCost {
        todo!()
    }
}

impl<F, MvPCS, UvPCS> ProverLpNode<F, MvPCS, UvPCS> for ProverFilterNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    /// Constructs a proof plan node from a DataFusion logical plan.
    fn from_lp(
        ctx: &SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        plan: datafusion_expr::LogicalPlan,
        parent_node_id: NodeId,
    ) -> Self {
        // Get the filter object from the logical plan
        let filter = match &plan {
            LogicalPlan::Filter(f) => f,
            _ => panic!("expected filter logical plan"),
        }
        .clone();
        // Build the node id for this filter node
        let node_id = NodeId::LP(plan.clone());
        // Recurse into the input subtree and fetch the logical plan that feeds this
        // filter.
        let input = ProverProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            prover_ctx.clone(),
            &filter.input,
            &Some(node_id.clone()),
        )
        .root()
        .clone();

        let predicate = ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
            ctx,
            prover_ctx.clone(),
            filter.predicate.clone(),
            &Some(node_id.clone()),
        )
        .root()
        .clone();

        ProverFilterNode {
            filter,
            input,
            predicate,
        }
    }
}

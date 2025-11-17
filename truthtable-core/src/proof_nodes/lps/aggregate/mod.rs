use std::sync::Arc;

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::prelude::SessionContext;
use datafusion_expr::{Aggregate, LogicalPlan};

use crate::{
    proof_nodes::{
        HintGenerationPlan,
        prover::{ProverGadgetNode, ProverLpNode, ProverPlanNode},
        verifier::VerifierNode,
    },
    prover::trees::proof_tree::ProverProofTree,
    tree::{Node, NodeId, Tree},
};

mod hints;
pub struct ProverAggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub group_exprs: Vec<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>>,
    pub aggr_exprs: Vec<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>>,
    pub input: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    pub aggregate: Aggregate,
}

pub struct VerifierAggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub group_exprs: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    pub aggr_exprs: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    pub input: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub aggregate: Aggregate,
}

impl<F, MvPCS, UvPCS> Node<F, MvPCS, UvPCS> for ProverAggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn children(&self) -> Vec<Arc<dyn Node<F, MvPCS, UvPCS>>> {
        todo!()
    }

    fn node_id(&self) -> NodeId {
        NodeId::LP(LogicalPlan::Aggregate(self.aggregate.clone()))
    }
}

impl<F, MvPCS, UvPCS> ProverGadgetNode<F, MvPCS, UvPCS> for ProverAggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn hint_generation_plans(
        &self,
        _proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> indexmap::IndexMap<String, HintGenerationPlan> {
        todo!()
    }

    fn arithmetic_post_process(&self) {
        todo!()
    }

    fn add_virtual_witness(&self, prover: &mut ark_piop::prover::ArgProver<F, MvPCS, UvPCS>) {
        todo!()
    }

    fn prove_piop(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<F, MvPCS, UvPCS>,
    ) -> ark_piop::errors::SnarkResult<()> {
        todo!()
    }

    fn cost(
        &self,
        statistics: datafusion::common::Statistics,
        schema: datafusion::arrow::datatypes::SchemaRef,
    ) -> crate::proof_nodes::cost::ProvingCost {
        todo!()
    }
}

impl<F, MvPCS, UvPCS> ProverPlanNode<F, MvPCS, UvPCS> for ProverAggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn output(&self, proof_tree: &ProverProofTree<F, MvPCS, UvPCS>) -> HintGenerationPlan {
        // Get the output of the child node as the input hint generation plan
        let input_hint_generation_plan = self.input.output(proof_tree);
        // Extract the data frame from the input hint generation plan
        let input = input_hint_generation_plan.data_frame();
        let output = hints::build_output_dataframe(input, &self.aggregate);
        HintGenerationPlan::new_virtual(output)
    }

    fn ctx_lp_node(
        &self,
        _proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>> {
        self.input.clone()
    }

    fn plan_children(&self) -> Vec<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>> {
        todo!()
    }
}

impl<F, MvPCS, UvPCS> ProverLpNode<F, MvPCS, UvPCS> for ProverAggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn from_lp(
        ctx: &SessionContext,
        prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        // Get the aggregate object from the logical plan
        let aggregate = match &plan {
            LogicalPlan::Aggregate(p) => p,
            _ => panic!("expected aggregate logical plan"),
        }
        .clone();
        // Build the node id for this aggregate node
        let node_id = NodeId::LP(plan.clone());
        // Recurse into the input subtree and fetch the logical plan that feeds this
        // aggregate.
        let input_prover_node = ProverProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            prover_ctx.clone(),
            &aggregate.input,
            &Some(node_id.clone()),
        )
        .root()
        .clone();

        // Recursively build prover nodes for each group expression
        let group_exprs = aggregate
            .group_expr
            .iter()
            .map(|expr| {
                ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    expr.clone(),
                    &Some(node_id.clone()),
                )
                .root()
                .clone()
            })
            .collect::<Vec<_>>();

        // Recursively build prover nodes for each aggregate expression
        let aggr_exprs = aggregate
            .aggr_expr
            .iter()
            .map(|expr| {
                ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    expr.clone(),
                    &Some(node_id.clone()),
                )
                .root()
                .clone()
            })
            .collect::<Vec<_>>();

        Self {
            group_exprs,
            aggr_exprs,
            input: input_prover_node,
            aggregate,
        }
    }
}

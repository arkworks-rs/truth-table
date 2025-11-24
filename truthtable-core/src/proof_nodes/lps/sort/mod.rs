mod gadget;
mod output;
use std::sync::Arc;

use arithmetic::ctx::SharedCtx;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    prover::ArgProver,
};
use datafusion::arrow::datatypes::SchemaRef;
use datafusion_common::Statistics;
use datafusion_expr::{LogicalPlan, Sort};

use crate::{
    proof_nodes::{
        HintDF,
        cost::ProvingCost,
        prover::{ProverLpNode, ProverPlanNode},
        verifier::VerifierNode,
    },
    prover::trees::{gadget_tree::GadgetTree, proof_tree::ProverProofTree},
    tree::{NodeId, ProverPlanTree},
};

pub struct ProverSortNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    input: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    sort: Sort,
}

pub struct VerifierSortNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    input: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    sort: Sort,
}

impl<F, MvPCS, UvPCS> ProverPlanNode<F, MvPCS, UvPCS> for ProverSortNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    fn gadget_tree(&self) -> GadgetTree<F, MvPCS, UvPCS> {
        GadgetTree::new(Arc::new(gadget::Prover::new()))
    }

    fn node_id(&self) -> NodeId {
        NodeId::LP(LogicalPlan::Sort(self.sort.clone()))
    }

    fn children(&self) -> Vec<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>> {
        vec![self.input.clone()]
    }

    fn output(&self, proof_tree: &ProverProofTree<F, MvPCS, UvPCS>) -> HintDF {
        // Get the output of the child node as the input hint generation plan
        let input_hint_generation_plan = self.input.output(proof_tree);
        // Extract the data frame from the input hint generation plan
        let input = input_hint_generation_plan.data_frame();
        let output = output::build_output_dataframe(input, &self.sort);
        HintDF::new_virtual(output)
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

    fn cost(&self, statistics: Statistics, schema: SchemaRef) -> ProvingCost {
        todo!()
    }
}

impl<F, MvPCS, UvPCS> ProverLpNode<F, MvPCS, UvPCS> for ProverSortNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn from_lp(
        ctx: &datafusion::prelude::SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        _parent: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        let sort = match plan.clone() {
            LogicalPlan::Sort(s) => s,
            _ => panic!("Expected LogicalPlan::Sort"),
        };
        let node_id = NodeId::LP(plan.clone());
        let input = ProverProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            prover_ctx.clone(),
            &sort.input,
            &Some(node_id.clone()),
        )
        .root()
        .clone();
        Self { input, sort }
    }
}

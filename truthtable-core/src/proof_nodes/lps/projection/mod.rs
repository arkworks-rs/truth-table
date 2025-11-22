use crate::proof_nodes::HintDF;
use crate::proof_nodes::prover::ProverLpNode;
use crate::proof_nodes::{prover::ProverPlanNode, verifier::VerifierNode};
use crate::prover::trees::proof_tree::ProverProofTree;
use crate::tree::NodeId;
use crate::tree::ProverPlanTree;
use arithmetic::ctx::SharedCtx;
use ark_ff::PrimeField;
use ark_piop::prover::ArgProver;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::{logical_expr::LogicalPlan, prelude::SessionContext};
use datafusion_common::Statistics;
use datafusion_expr::Projection;
use std::sync::Arc;
pub(super) mod hints;

pub struct ProverProjectionNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    projection: Projection,
    input: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    expr: Vec<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>>,
}
pub struct VerifierProjectionNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    projection: Projection,
    input: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    expr: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
}

impl<F, MvPCS, UvPCS> ProverPlanNode<F, MvPCS, UvPCS> for ProverProjectionNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn node_id(&self) -> NodeId {
        NodeId::LP(LogicalPlan::Projection(self.projection.clone()))
    }

    fn arithmetic_post_process(&self) {
        todo!()
    }

    fn add_virtual_witness(&self, prover: &mut ArgProver<F, MvPCS, UvPCS>) {
        todo!()
    }


    fn cost(
        &self,
        statistics: Statistics,
        schema: SchemaRef,
    ) -> crate::proof_nodes::cost::ProvingCost {
        todo!()
    }

    fn output(&self, proof_tree: &ProverProofTree<F, MvPCS, UvPCS>) -> HintDF {
        // Get the output of the child node as the input hint generation plan
        let input_hint_generation_plan = self.input.output(proof_tree);
        // Extract the data frame from the input hint generation plan
        let input = input_hint_generation_plan.data_frame();
        let output = hints::build_output_dataframe(input, &self.projection);
        HintDF::new_virtual(output)
    }

    fn ctx_lp_node(
        &self,
        proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>> {
        self.input.clone()
    }

    fn children(&self) -> Vec<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>> {
        let mut children = Vec::with_capacity(1 + self.expr.len());
        children.push(self.input.clone());
        self.expr.iter().for_each(|e| children.push(e.clone()));
        children
    }
    
    fn gadget_forest(&self) -> crate::prover::trees::gadget_tree::GadgetForest<F, MvPCS, UvPCS> {
        todo!()
    }
}

impl<F, MvPCS, UvPCS> ProverLpNode<F, MvPCS, UvPCS> for ProverProjectionNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn from_lp(
        ctx: &SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        // Get the projection object from the logical plan
        let projection = match &plan {
            LogicalPlan::Projection(p) => p,
            _ => panic!("expected projection logical plan"),
        }
        .clone();
        // Build the node id for this projection node
        let node_id = NodeId::LP(plan.clone());
        // Recurse into the input subtree and fetch the logical plan that feeds this
        // projection.
        let input = ProverProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            prover_ctx.clone(),
            &projection.input,
            &Some(node_id.clone()),
        )
        .root()
        .clone();

        // Build expression proof plans for the projection expressions (excluding the
        // retained activator).
        let expr = projection
            .expr
            .clone()
            .into_iter()
            .map(|expr| {
                ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    expr,
                    &Some(node_id.clone()),
                )
                .root()
                .clone()
            })
            .collect();
        Self {
            projection,
            input,
            expr,
        }
    }
}

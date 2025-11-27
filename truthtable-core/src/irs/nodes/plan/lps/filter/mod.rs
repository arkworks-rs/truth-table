use std::sync::Arc;

use arithmetic::ctx::SharedCtx;
use ark_ff::PrimeField;
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    prover::ArgProver,
};
use datafusion::{arrow::datatypes::SchemaRef, prelude::SessionContext};
use datafusion_common::Statistics;
use datafusion_expr::{Filter, LogicalPlan};

use crate::irs::tree::PlanNode;

/// The implementation of a filter node in the prover proof tree.
pub struct ProverFilterNode<B>
where
    B: SnarkBackend,
{
    // The filter information from DataFusion
    filter: Filter,
    // The prover plan children nodes for the Filter expressions
    input: Arc<dyn PlanNode<B>>,
    // The prover predicate expression node for the filter condition
    predicate: Arc<dyn PlanNode<B>>,
}

// impl<B> ProverPlanNode<B> for ProverFilterNode<B>
// where
//     F: PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
// {
//     fn node_id(&self) -> NodeId {
//         NodeId::LP(LogicalPlan::Filter(self.filter.clone()))
//     }
//     fn output(&self, _proof_tree: &ProverProofTree<B>) -> HintDF {
//         todo!()
//     }

//     fn ctx_lp_node(
//         &self,
//         proof_tree: &ProverProofTree<B>,
//     ) -> Arc<dyn ProverPlanNode<B>> {
//         todo!()
//     }

//     fn arithmetic_post_process(&self) {
//         todo!()
//     }

//     fn add_virtual_witness(&self, prover: &mut ArgProver<B>) {
//         todo!()
//     }

//     fn cost(&self, statistics: Statistics, schema: SchemaRef) -> ProvingCost {
//         todo!()
//     }

//     fn children(&self) -> Vec<Arc<dyn ProverPlanNode<B>>> {
//         vec![self.input.clone(), self.predicate.clone()]
//     }

//     fn gadget_tree(&self) -> crate::prover::trees::gadget_tree::GadgetTree<B> {
//         todo!()
//     }
// }

// impl<B> ProverLpNode<B> for ProverFilterNode<B>
// where
//     F: PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
// {
//     /// Constructs a proof plan node from a DataFusion logical plan.
//     fn from_lp(
//         ctx: &SessionContext,
//         prover_ctx: SharedCtx<B>,
//         plan: datafusion_expr::LogicalPlan,
//         parent_node_id: NodeId,
//     ) -> Self {
//         // Get the filter object from the logical plan
//         let filter = match &plan {
//             LogicalPlan::Filter(f) => f,
//             _ => panic!("expected filter logical plan"),
//         }
//         .clone();
//         // Build the node id for this filter node
//         let node_id = NodeId::LP(plan.clone());
//         // Recurse into the input subtree and fetch the logical plan that feeds this
//         // filter.
//         let input = ProverProofTree::<B>::from_lp(
//             ctx,
//             prover_ctx.clone(),
//             &filter.input,
//             &Some(node_id.clone()),
//         )
//         .root()
//         .clone();

//         let predicate = ProverProofTree::<B>::from_expr(
//             ctx,
//             prover_ctx.clone(),
//             filter.predicate.clone(),
//             &Some(node_id.clone()),
//         )
//         .root()
//         .clone();

//         ProverFilterNode {
//             filter,
//             input,
//             predicate,
//         }
//     }
// }

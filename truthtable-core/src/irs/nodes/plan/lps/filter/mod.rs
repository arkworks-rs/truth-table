use std::sync::Arc;

use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion_common::Statistics;
use datafusion_expr::{Filter, LogicalPlan};
use derivative::Derivative;

use crate::irs::{
    nodes::{
        cost::ProvingCost,
        hints::HintDF,
        id::{NodeId, PlanNodeId},
    },
    tree::{Gadget, LpNode, Node, PlanNode, Tree},
};

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
/// The implementation of a filter node in the prover proof tree.
pub struct ProverNode<B>
where
    B: SnarkBackend,
{
    // The filter information from DataFusion
    filter: Filter,
    // The prover plan children nodes for the Filter expressions
    input: Arc<dyn Node<B>>,
    // The prover predicate expression node for the filter condition
    predicate: Arc<dyn Node<B>>,
}

impl<B: SnarkBackend> Node<B> for ProverNode<B> {
    fn id(&self) -> NodeId {
        NodeId::PLAN(PlanNodeId::LP(LogicalPlan::Filter(self.filter.clone())))
    }

    fn name(&self) -> String {
        "Filter".to_string()
    }

    fn cost(&self, statistics: Statistics, schema: SchemaRef) -> ProvingCost {
        todo!()
    }

    fn as_plan_node(&self) -> Option<&dyn PlanNode<B>> {
        Some(self)
    }

    fn as_gadget_node(&self) -> Option<&dyn Gadget<B>> {
        None
    }
}

impl<B: SnarkBackend> PlanNode<B> for ProverNode<B> {
    fn children(&self) -> Vec<Arc<dyn Node<B>>> {
        vec![self.input.clone(), self.predicate.clone()]
    }

    fn gadget(&self) -> Arc<dyn Gadget<B>> {
        todo!()
    }

    fn output(&self) -> HintDF {
        todo!()
    }
}

impl<B: SnarkBackend> LpNode<B> for ProverNode<B> {
    fn from_lp(plan: LogicalPlan) -> Self
    where
        Self: Sized,
    {
        // Get the filter object from the logical plan
        let filter = match &plan {
            LogicalPlan::Filter(f) => f,
            _ => panic!("expected filter logical plan"),
        }
        .clone();

        // Build the node id for this projection node
        let node_id = NodeId::PLAN(PlanNodeId::LP(plan.clone()));

        // Recurse into the input subtree and fetch the logical plan that feeds this
        // filter.
        let input = Tree::<B>::from_logical_plan(&filter.input).root().clone();

        let predicate = Tree::<B>::from_expr(&filter.predicate, Some(node_id.clone()))
            .root()
            .clone();

        ProverNode {
            filter,
            input,
            predicate,
        }
    }
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

//     }
// }

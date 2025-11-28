use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::logical_expr::LogicalPlan;
use datafusion_common::Statistics;
use datafusion_expr::Projection;
use derivative::Derivative;
use std::sync::Arc;

use crate::irs::nodes::id::{NodeId, PlanNodeId};
use crate::irs::tree::{LpNode, Node, PlanNode, Tree};
pub(super) mod hints;

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct ProverNode<B>
where
    B: SnarkBackend,
{
    projection: Projection,
    input: Arc<dyn Node<B>>,
    expr: Vec<Arc<dyn Node<B>>>,
}

impl<B: SnarkBackend> Node<B> for ProverNode<B> {
    fn id(&self) -> crate::irs::nodes::id::NodeId {
        NodeId::PLAN(PlanNodeId::LP(LogicalPlan::Projection(
            self.projection.clone(),
        )))
    }

    fn cost(
        &self,
        statistics: Statistics,
        schema: SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn as_plan_node(&self) -> Option<&dyn PlanNode<B>> {
        Some(self)
    }

    fn as_gadget_node(&self) -> Option<&dyn crate::irs::tree::Gadget<B>> {
        None
    }

    fn name(&self) -> String {
        "Projection".to_string()
    }
}

impl<B: SnarkBackend> PlanNode<B> for ProverNode<B> {
    fn children(&self) -> Vec<Arc<dyn Node<B>>> {
        let mut children: Vec<Arc<dyn Node<B>>> = Vec::with_capacity(1 + self.expr.len());
        children.push(Arc::clone(&self.input));
        children.extend(self.expr.iter().cloned());
        children
    }

    fn gadget(&self) -> Arc<dyn crate::irs::tree::Gadget<B>> {
        todo!()
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        todo!()
    }
}

impl<B: SnarkBackend> LpNode<B> for ProverNode<B> {
    fn from_lp(plan: LogicalPlan) -> Self
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
        let node_id = NodeId::PLAN(PlanNodeId::LP(plan.clone()));
        // Recurse into the input subtree and fetch the logical plan that feeds this
        // projection.
        let input = Tree::<B>::from_logical_plan(&projection.input).root();

        // Build expression proof plans for the projection expressions (excluding the
        // retained activator).
        let expr = projection
            .expr
            .clone()
            .into_iter()
            .map(|expr| Tree::<B>::from_expr(&expr, Some(node_id.clone())).root())
            .collect();
        Self {
            projection,
            input,
            expr,
        }
    }
}

// impl<B> ProverPlanNode<B> for ProverNode<B>
// where
//     F: PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
// {
//     fn node_id(&self) -> NodeId {
//         NodeId::LP(LogicalPlan::Projection(self.projection.clone()))
//     }

//     fn arithmetic_post_process(&self) {
//         todo!()
//     }

//     fn add_virtual_witness(&self, prover: &mut ArgProver<B>) {
//         todo!()
//     }

//     fn cost(
//         &self,
//         statistics: Statistics,
//         schema: SchemaRef,
//     ) -> crate::nodes::cost::ProvingCost {
//         todo!()
//     }

//     fn output(&self, proof_tree: &ProverProofTree<B>) -> HintDF {
//         // Get the output of the child node as the input hint generation plan
//         let input_hint_generation_plan = self.input.output(proof_tree);
//         // Extract the data frame from the input hint generation plan
//         let input = input_hint_generation_plan.data_frame();
//         let output = hints::build_output_dataframe(input, &self.projection);
//         HintDF::new_virtual(output)
//     }

//     fn ctx_lp_node(
//         &self,
//         proof_tree: &ProverProofTree<B>,
//     ) -> Arc<dyn ProverPlanNode<B>> {
//         self.input.clone()
//     }

//     fn children(&self) -> Vec<Arc<dyn ProverPlanNode<B>>> {
//         let mut children = Vec::with_capacity(1 + self.expr.len());
//         children.push(self.input.clone());
//         self.expr.iter().for_each(|e| children.push(e.clone()));
//         children
//     }

//     fn gadget_tree(&self) -> crate::prover::trees::gadget_tree::GadgetTree<B> {
//         todo!()
//     }
// }

// impl<B> ProverLpNode<B> for ProverNode<B>
// where
//     F: PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
// {
//     fn from_lp(
//         ctx: &SessionContext,
//         prover_ctx: SharedCtx<B>,
//         plan: LogicalPlan,
//         parent_node_id: NodeId,
//     ) -> Self
//     where
//         Self: Sized,
//     {
//         // Get the projection object from the logical plan
//         let projection = match &plan {
//             LogicalPlan::Projection(p) => p,
//             _ => panic!("expected projection logical plan"),
//         }
//         .clone();
//         // Build the node id for this projection node
//         let node_id = NodeId::LP(plan.clone());
//         // Recurse into the input subtree and fetch the logical plan that feeds this
//         // projection.
//         let input = ProverProofTree::<B>::from_lp(
//             ctx,
//             prover_ctx.clone(),
//             &projection.input,
//             &Some(node_id.clone()),
//         )
//         .root()
//         .clone();

//         // Build expression proof plans for the projection expressions (excluding the
//         // retained activator).
//         let expr = projection
//             .expr
//             .clone()
//             .into_iter()
//             .map(|expr| {
//                 ProverProofTree::<B>::from_expr(
//                     ctx,
//                     prover_ctx.clone(),
//                     expr,
//                     &Some(node_id.clone()),
//                 )
//                 .root()
//                 .clone()
//             })
//             .collect();
//         Self {
//             projection,
//             input,
//             expr,
//         }
//     }
// }

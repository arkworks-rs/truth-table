use std::sync::Arc;

use arithmetic::{ACTIVATOR_EXPR, ctx::SharedCtx};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::prelude::SessionContext;
use datafusion_expr::{Expr, LogicalPlan, expr::Alias};

use crate::nodes::id::NodeId;
use crate::nodes::prover::{ProverExprNode, ProverGadget, ProverPlanNode};
#[derive(Clone)]
pub struct ProverAliasExprNode {
    pub parent_node_id: NodeId,
    pub alias: Alias,
}
#[derive(Clone)]
pub struct VerifierAliasExprNode {
    pub parent_node_id: NodeId,
    pub alias: Alias,
}

// impl<B> ProverPlanNode<B> for ProverAliasExprNode
// where
//     F: PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
// {
//     fn node_id(&self) -> NodeId {
//         NodeId::Expr(Expr::Alias(self.alias.clone()))
//     }
//     fn arithmetic_post_process(&self) {
//         todo!()
//     }

//     fn add_virtual_witness(&self, prover: &mut ark_piop::prover::ArgProver<B>) {
//         todo!()
//     }

//     fn cost(
//         &self,
//         statistics: datafusion::common::Statistics,
//         schema: datafusion::arrow::datatypes::SchemaRef,
//     ) -> crate::nodes::cost::ProvingCost {
//         todo!()
//     }

//     fn output(&self, proof_tree: &ProverProofTree<B>) -> HintDF {
//         let ctx_lp_node = self.ctx_lp_node(proof_tree);
//         let base_hint_generation_plan = ctx_lp_node.output(proof_tree);
//         let base_data_frame = base_hint_generation_plan.data_frame();
//         let projection_exprs = vec![Expr::Alias(self.alias.clone()), ACTIVATOR_EXPR.clone()];
//         let projected_data_frame = base_data_frame.clone().select(projection_exprs).unwrap();
//         HintDF::new_virtual(projected_data_frame)
//     }

//     fn ctx_lp_node(
//         &self,
//         proof_tree: &ProverProofTree<B>,
//     ) -> Arc<dyn ProverPlanNode<B>> {
//         proof_tree
//             .get_node(&self.parent_node_id)
//             .unwrap()
//             .ctx_lp_node(proof_tree)
//     }

//     fn children(&self) -> Vec<Arc<dyn ProverPlanNode<B>>> {
//         vec![]
//     }

//     fn gadget_tree(&self) -> crate::prover::trees::gadget_tree::GadgetTree<B> {
//         todo!()
//     }
// }

// impl<B> ProverExprNode<B> for ProverAliasExprNode
// where
//     F: PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
// {
//     fn from_expr(
//         _ctx: &SessionContext,
//         _prover_ctx: SharedCtx<B>,
//         _expr: datafusion::logical_expr::Expr,
//         parent_node_id: NodeId,
//     ) -> Self
//     where
//         Self: Sized,
//     {
//         let alias = match _expr {
//             Expr::Alias(col) => col,
//             _ => panic!(),
//         };
//         Self {
//             parent_node_id,
//             alias,
//         }
//     }
// }

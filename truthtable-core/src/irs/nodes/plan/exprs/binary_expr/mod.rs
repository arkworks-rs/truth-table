use std::sync::Arc;

use crate::nodes::id::NodeId;
use crate::nodes::prover::{ProverExprNode, ProverPlanNode};
use arithmetic::ACTIVATOR_EXPR;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion_expr::Expr;
use datafusion_expr::{BinaryExpr, LogicalPlan};
#[derive(Clone)]
pub struct ProverBinaryExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub binary_expression: BinaryExpr,
    pub left: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    pub right: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    pub parent: NodeId,
}
// impl<F, MvPCS, UvPCS> ProverBinaryExprNode<F, MvPCS, UvPCS>
// where
//     F: PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static,
// {
//     fn try_project(&self, hint_df: &HintDF) -> Option<HintDF> {
//         let projection_exprs = vec![
//             Expr::BinaryExpr(self.binary_expression.clone()),
//             ACTIVATOR_EXPR.clone(),
//         ];
//         hint_df
//             .data_frame()
//             .clone()
//             .select(projection_exprs)
//             .ok()
//             .map(HintDF::new_virtual)
//     }
// }
// impl<F, MvPCS, UvPCS> ProverPlanNode<F, MvPCS, UvPCS> for ProverBinaryExprNode<F, MvPCS, UvPCS>
// where
//     F: PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
// {
//     fn node_id(&self) -> crate::tree::NodeId {
//         NodeId::Expr(Expr::BinaryExpr(self.binary_expression.clone()))
//     }
//     fn output(&self, proof_tree: &ProverProofTree<F, MvPCS, UvPCS>) -> HintDF {
//         let ctx_df = self.ctx_lp_node(proof_tree).output(proof_tree);
//         if let Some(projected) = self.try_project(&ctx_df) {
//             return projected;
//         }

//         for (node_id, node) in proof_tree.arena().iter() {
//             if matches!(node_id, NodeId::LP(LogicalPlan::TableScan(_))) {
//                 let scan_df = node.output(proof_tree);
//                 if let Some(projected) = self.try_project(&scan_df) {
//                     return projected;
//                 }
//             }
//         }

//         panic!(
//             "failed to project binary expression {:?} against any available plan",
//             self.binary_expression
//         );
//     }

//     fn ctx_lp_node(
//         &self,
//         proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
//     ) -> Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>> {
//         todo!()
//     }

//     fn arithmetic_post_process(&self) {
//         todo!()
//     }

//     fn add_virtual_witness(&self, prover: &mut ark_piop::prover::ArgProver<F, MvPCS, UvPCS>) {
//         todo!()
//     }

//     fn cost(
//         &self,
//         statistics: datafusion_common::Statistics,
//         schema: datafusion::arrow::datatypes::SchemaRef,
//     ) -> crate::nodes::cost::ProvingCost {
//         todo!()
//     }

//     fn children(&self) -> Vec<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>> {
//         vec![self.left.clone(), self.right.clone()]
//     }

//     fn gadget_tree(&self) -> crate::prover::trees::gadget_tree::GadgetTree<F, MvPCS, UvPCS> {
//         todo!()
//     }
// }

// impl<F, MvPCS, UvPCS> ProverExprNode<F, MvPCS, UvPCS> for ProverBinaryExprNode<F, MvPCS, UvPCS>
// where
//     F: PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
// {
//     fn from_expr(
//         ctx: &datafusion::prelude::SessionContext,
//         prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
//         expr: Expr,
//         parent: NodeId,
//     ) -> Self
//     where
//         Self: Sized,
//     {
//         // Get the Binary Expression
//         let binary_expression = match expr.clone() {
//             Expr::BinaryExpr(b) => b,
//             _ => panic!("expected binary expression"),
//         };

//         // Builf the id for the current node
//         let node_id = NodeId::Expr(expr.clone());
//         // Recursively build the left child node
//         let left = ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
//             ctx,
//             prover_ctx.clone(),
//             binary_expression.left.as_ref().clone(),
//             &Some(node_id.clone()),
//         )
//         .root()
//         .clone();
//         // Recursively build the right child node
//         let right = ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
//             ctx,
//             prover_ctx.clone(),
//             binary_expression.right.as_ref().clone(),
//             &Some(node_id),
//         )
//         .root()
//         .clone();

//         Self {
//             binary_expression,
//             left,
//             right,
//             parent,
//         }
//     }
// }

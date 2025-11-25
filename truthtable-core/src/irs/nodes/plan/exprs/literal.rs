use std::sync::Arc;

use crate::nodes::id::NodeId;
use arithmetic::ctx::SharedCtx;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion_common::ScalarValue;
use datafusion_expr::Expr;
#[derive(Clone)]
pub struct ProverLiteralExprNode {
    pub literal: ScalarValue,
    pub parent_node_id: NodeId,
}

// impl<F, MvPCS, UvPCS> crate::nodes::prover::ProverPlanNode<F, MvPCS, UvPCS>
//     for ProverLiteralExprNode
// where
//     F: ark_ff::PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
// {
//     fn node_id(&self) -> NodeId {
//         NodeId::Expr(Expr::Literal(self.literal.clone()))
//     }
//     fn output(
//         &self,
//         _proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
//     ) -> crate::nodes::HintDF {
//         todo!()
//     }

//     fn ctx_lp_node(
//         &self,
//         proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
//     ) -> std::sync::Arc<dyn crate::nodes::prover::ProverPlanNode<F, MvPCS, UvPCS>> {
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
//         vec![]
//     }

//     fn gadget_tree(&self) -> crate::prover::trees::gadget_tree::GadgetTree<F, MvPCS, UvPCS> {
//         todo!()
//     }
// }

// impl<F, MvPCS, UvPCS> crate::nodes::prover::ProverExprNode<F, MvPCS, UvPCS>
//     for ProverLiteralExprNode
// where
//     F: ark_ff::PrimeField,
//     MvPCS: ark_piop::pcs::PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
//     UvPCS: ark_piop::pcs::PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
// {
//     fn from_expr(
//         ctx: &datafusion::execution::context::SessionContext,
//         prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
//         expr: datafusion_expr::Expr,
//         parent_node_id: NodeId,
//     ) -> Self {
//         let literal = match expr {
//             Expr::Literal(literal) => literal,
//             _ => panic!(),
//         };
//         Self {
//             literal,
//             parent_node_id,
//         }
//     }
// }

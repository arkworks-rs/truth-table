use std::sync::Arc;

use arithmetic::ctx::SharedCtx;
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion_common::ScalarValue;
use datafusion_expr::Expr;

use crate::irs::{
    nodes::id::NodeId,
    tree::{ExprNode, Node, PlanNode},
};
#[derive(Debug)]
pub struct ProverNode {
    pub literal: ScalarValue,
    pub parent_node_id: NodeId,
}

impl<B: SnarkBackend> Node<B> for ProverNode {
    fn id(&self) -> NodeId {
        todo!()
    }

    fn cost(
        &self,
        statistics: datafusion_common::Statistics,
        schema: datafusion::arrow::datatypes::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn as_plan_node(&self) -> Option<&dyn crate::irs::tree::PlanNode<B>> {
        todo!()
    }

    fn as_gadget_node(&self) -> Option<&dyn crate::irs::tree::Gadget<B>> {
        todo!()
    }
}

impl<B: SnarkBackend> PlanNode<B> for ProverNode {
    fn children(&self) -> Vec<Arc<dyn Node<B>>> {
        Vec::new()
    }

    fn gadget(&self) -> Arc<dyn crate::irs::tree::Gadget<B>> {
        todo!()
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        todo!()
    }
}

impl<B: SnarkBackend> ExprNode<B> for ProverNode {
    fn from_expr(_expr: Expr) -> Self
    where
        Self: Sized,
    {
        todo!()
    }
}

// impl<B> crate::nodes::prover::ProverPlanNode<B>
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
//         _proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<B>,
//     ) -> crate::nodes::HintDF {
//         todo!()
//     }

//     fn ctx_lp_node(
//         &self,
//         proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<B>,
//     ) -> std::sync::Arc<dyn crate::nodes::prover::ProverPlanNode<B>> {
//         todo!()
//     }

//     fn arithmetic_post_process(&self) {
//         todo!()
//     }

//     fn add_virtual_witness(&self, prover: &mut ark_piop::prover::ArgProver<B>) {
//         todo!()
//     }

//     fn cost(
//         &self,
//         statistics: datafusion_common::Statistics,
//         schema: datafusion::arrow::datatypes::SchemaRef,
//     ) -> crate::nodes::cost::ProvingCost {
//         todo!()
//     }

//     fn children(&self) -> Vec<Arc<dyn ProverPlanNode<B>>> {
//         vec![]
//     }

//     fn gadget_tree(&self) -> crate::prover::trees::gadget_tree::GadgetTree<B> {
//         todo!()
//     }
// }

// impl<B> crate::nodes::prover::ProverExprNode<B>
//     for ProverLiteralExprNode
// where
//     F: ark_ff::PrimeField,
//     MvPCS: ark_piop::pcs::PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
//     UvPCS: ark_piop::pcs::PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
// {
//     fn from_expr(
//         ctx: &datafusion::execution::context::SessionContext,
//         prover_ctx: SharedCtx<B>,
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

use std::sync::Arc;

use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion_common::{ScalarValue, Statistics};
use datafusion_expr::Expr;

use crate::irs::{
    nodes::{
        cost::ProvingCost,
        hints::HintDF,
        id::{NodeId, PlanNodeId},
    },
    tree::{ExprNode, Gadget, Node, PlanNode},
};
#[derive(Debug)]
pub struct ProverNode {
    pub literal: ScalarValue,
    pub parent: NodeId,
}

impl<B: SnarkBackend> Node<B> for ProverNode {
    fn id(&self) -> NodeId {
        NodeId::PLAN(PlanNodeId::EXPR(Expr::Literal(self.literal.clone())))
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

    fn name(&self) -> String {
        "Literal".to_string()
    }
}

impl<B: SnarkBackend> PlanNode<B> for ProverNode {
    fn children(&self) -> Vec<Arc<dyn Node<B>>> {
        Vec::new()
    }

    fn gadget(&self) -> Arc<dyn Gadget<B>> {
        todo!()
    }

    fn output(&self) -> HintDF {
        todo!()
    }
}

impl<B: SnarkBackend> ExprNode<B> for ProverNode {
    fn from_expr(expr: Expr, parent: Option<NodeId>) -> Self
    where
        Self: Sized,
    {
        let literal = match expr {
            Expr::Literal(literal) => literal,
            _ => panic!(),
        };
        Self {
            literal,
            parent: parent.unwrap(),
        }
    }

    fn parent(&self) -> Arc<dyn PlanNode<B>>
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

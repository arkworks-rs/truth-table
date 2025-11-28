use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion_common::Statistics;
use datafusion_expr::{BinaryExpr, Expr};
use derivative::Derivative;
use std::sync::Arc;

use crate::irs::{
    nodes::{
        cost::ProvingCost,
        id::{NodeId, PlanNodeId},
    },
    tree::{ExprNode, Gadget, Node, PlanNode, Tree},
};
#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct ProverNode<B> {
    pub binary_expression: BinaryExpr,
    pub left: Arc<dyn Node<B>>,
    pub right: Arc<dyn Node<B>>,
    pub parent: NodeId,
}

impl<B: SnarkBackend> Node<B> for ProverNode<B> {
    fn id(&self) -> NodeId {
        NodeId::PLAN(PlanNodeId::EXPR(Expr::BinaryExpr(
            self.binary_expression.clone(),
        )))
    }

    fn name(&self) -> String {
        "BinaryExpr".to_string()
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
        vec![self.left.clone(), self.right.clone()]
    }

    fn gadget(&self) -> Arc<dyn Gadget<B>> {
        todo!()
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        todo!()
    }
}

impl<B: SnarkBackend> ExprNode<B> for ProverNode<B> {
    fn from_expr(expr: Expr, parent: Option<NodeId>) -> Self
    where
        Self: Sized,
    {
        // Get the Binary Expression
        let binary_expression = match expr.clone() {
            Expr::BinaryExpr(b) => b,
            _ => panic!("expected binary expression"),
        };

        // Builf the id for the current node
        let node_id = NodeId::PLAN(PlanNodeId::EXPR(expr));
        // Recursively build the left child node
        let left = Tree::<B>::from_expr(&binary_expression.left.as_ref(), Some(node_id.clone()))
            .root()
            .clone();
        // Recursively build the right child node
        let right = Tree::<B>::from_expr(&binary_expression.right.as_ref(), Some(node_id.clone()))
            .root()
            .clone();

        Self {
            binary_expression,
            left,
            right,
            parent: parent.unwrap(),
        }
    }
}

// impl<B> ProverBinaryExprNode<B>
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
// impl<B> ProverPlanNode<B> for ProverBinaryExprNode<B>
// where
//     F: PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
// {
//     fn node_id(&self) -> crate::tree::NodeId {
//         NodeId::Expr(Expr::BinaryExpr(self.binary_expression.clone()))
//     }
//     fn output(&self, proof_tree: &ProverProofTree<B>) -> HintDF {
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
//         proof_tree: &ProverProofTree<B>,
//     ) -> Arc<dyn ProverPlanNode<B>> {
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
//         vec![self.left.clone(), self.right.clone()]
//     }

//     fn gadget_tree(&self) -> crate::prover::trees::gadget_tree::GadgetTree<B> {
//         todo!()
//     }
// }

// impl<B> ProverExprNode<B> for ProverBinaryExprNode<B>
// where
//     F: PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
// {
//     fn from_expr(
//         ctx: &datafusion::prelude::SessionContext,
//         prover_ctx: arithmetic::ctx::SharedCtx<B>,
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
//         let left = ProverProofTree::<B>::from_expr(
//             ctx,
//             prover_ctx.clone(),
//             binary_expression.left.as_ref().clone(),
//             &Some(node_id.clone()),
//         )
//         .root()
//         .clone();
//         // Recursively build the right child node
//         let right = ProverProofTree::<B>::from_expr(
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

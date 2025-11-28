use std::sync::Arc;

use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion_common::{Column, Statistics};
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
    pub column: Column,
}

impl<B: SnarkBackend> Node<B> for ProverNode {
    fn id(&self) -> NodeId {
        NodeId::PLAN(PlanNodeId::EXPR(Expr::Column(self.column.clone())))
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
        "Column".to_string()
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
    fn from_expr(expr: Expr, _parent: Option<NodeId>) -> Self
    where
        Self: Sized,
    {
        let column = match expr {
            Expr::Column(col) => col,
            _ => panic!(),
        };
        Self { column }
    }

    fn parent(&self) -> Arc<dyn PlanNode<B>>
    where
        Self: Sized,
    {
        todo!()
    }
}

// impl<B> ProverPlanNode<B> for ProverColumnExprNode
// where
//     F: PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
// {
//     fn node_id(&self) -> NodeId {
//         NodeId::Expr(Expr::Column(self.column.clone()))
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
//         let projection_exprs = vec![Expr::Column(self.column.clone()), ACTIVATOR_EXPR.clone()];
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

// impl<B> ProverExprNode<B> for ProverColumnExprNode
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
//         let column = match _expr {
//             Expr::Column(col) => col,
//             _ => panic!(),
//         };
//         Self {
//             parent_node_id,
//             column,
//         }
//     }
// }

use std::marker::PhantomData;

use ark_piop::SnarkBackend;
use datafusion_expr::expr::AggregateFunction;

#[derive(Clone)]
pub struct ProverAggregateFunctionExprNode<B>
where
    B: SnarkBackend,
{
    aggregate_function: AggregateFunction,
    phantom: PhantomData<(B)>,
}
// impl<B> ProverPlanNode<B>
//     for ProverAggregateFunctionExprNode<B>
// where
//     F: PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
// {
//     fn gadget_tree(&self) -> crate::prover::trees::gadget_tree::GadgetTree<B> {
//         todo!()
//     }

//     fn node_id(&self) -> crate::tree::NodeId {
//         NodeId::Expr(Expr::AggregateFunction(self.aggregate_function.clone()))
//     }

//     fn children(&self) -> Vec<Arc<dyn ProverPlanNode<B>>> {
//         vec![]
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
// }

// impl<B> ProverExprNode<B>
//     for ProverAggregateFunctionExprNode<B>
// where
//     F: PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
// {
//     fn from_expr(
//         ctx: &datafusion::prelude::SessionContext,
//         prover_ctx: SharedCtx<B>,
//         expr: Expr,
//         parent: NodeId,
//     ) -> Self {
//         let aggregate_function = match expr {
//             Expr::AggregateFunction(f) => f,
//             _ => panic!("Expected AggregateFunction expression"),
//         };
//         Self {
//             aggregate_function,
//             phantom: PhantomData,
//         }
//     }
// }

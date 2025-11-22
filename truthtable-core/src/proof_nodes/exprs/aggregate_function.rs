use std::{marker::PhantomData, sync::Arc};

use arithmetic::ctx::SharedCtx;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion_expr::{Expr, expr::AggregateFunction};

use crate::{
    proof_nodes::prover::{ProverExprNode, ProverPlanNode},
    tree::NodeId,
};

#[derive(Clone)]
pub struct ProverAggregateFunctionExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    aggregate_function: AggregateFunction,
    phantom: PhantomData<(F, MvPCS, UvPCS)>,
}
#[derive(Clone)]
pub struct VerifierAggregateFunctionExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    aggregate_function: AggregateFunction,
    phantom: PhantomData<(F, MvPCS, UvPCS)>,
}

impl<F, MvPCS, UvPCS> ProverPlanNode<F, MvPCS, UvPCS>
    for ProverAggregateFunctionExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    fn gadget_forest(&self) -> crate::prover::trees::gadget_tree::GadgetForest<F, MvPCS, UvPCS> {
        todo!()
    }

    fn node_id(&self) -> crate::tree::NodeId {
        NodeId::Expr(Expr::AggregateFunction(self.aggregate_function.clone()))
    }

    fn children(&self) -> Vec<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>> {
        vec![]
    }

    fn output(
        &self,
        _proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> crate::proof_nodes::HintDF {
        todo!()
    }
    fn ctx_lp_node(
        &self,
        proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>> {
        todo!()
    }

    fn arithmetic_post_process(&self) {
        todo!()
    }

    fn add_virtual_witness(&self, prover: &mut ark_piop::prover::ArgProver<F, MvPCS, UvPCS>) {
        todo!()
    }

    fn cost(
        &self,
        statistics: datafusion_common::Statistics,
        schema: datafusion::arrow::datatypes::SchemaRef,
    ) -> crate::proof_nodes::cost::ProvingCost {
        todo!()
    }
}

impl<F, MvPCS, UvPCS> ProverExprNode<F, MvPCS, UvPCS>
    for ProverAggregateFunctionExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    fn from_expr(
        ctx: &datafusion::prelude::SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        parent: crate::tree::NodeId,
    ) -> Self {
        let aggregate_function = match expr {
            Expr::AggregateFunction(f) => f,
            _ => panic!("Expected AggregateFunction expression"),
        };
        Self {
            aggregate_function,
            phantom: PhantomData,
        }
    }
}

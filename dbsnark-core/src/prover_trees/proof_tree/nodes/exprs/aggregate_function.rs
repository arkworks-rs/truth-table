use crate::{
    id::NodeId,
    prover_trees::{piop_tree::ProverPIOPTree, proof_tree::ProverProofTree},
};
use std::{any::Any, sync::Arc};

use arithmetic::ctx::SharedCtx;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    prover::Prover,
};
use datafusion::{
    arrow::datatypes::SchemaRef, common::Statistics, logical_expr::Expr, prelude::SessionContext,
};
use datafusion_expr::LogicalPlan;

use crate::prover_trees::proof_tree::nodes::{ProverNode, cost::ProvingCost};

#[derive(Clone)]
pub struct AggregateFunctionExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub node_id: NodeId,
    pub inputs: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for AggregateFunctionExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        self.inputs.iter().collect()
    }

    fn from_expr(
        ctx: &SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        parent_logical_plan: LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        let aggregate_expr = match expr.clone() {
            Expr::AggregateFunction(agg) => agg,
            _ => panic!("expected aggregate function expression"),
        };

        let inputs = aggregate_expr
            .params
            .args
            .iter()
            .map(|arg| {
                ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    arg.clone(),
                    &parent_logical_plan,
                )
            })
            .collect();

        Self {
            node_id: NodeId::Expr(expr),
            inputs,
        }
    }

    fn cost(&self, _statistics: Statistics, _schema: SchemaRef) -> ProvingCost {
        todo!()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut Prover<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }
    fn prove_piop(
        &self,
        _prover: &mut Prover<F, MvPCS, UvPCS>,
        _piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        todo!()
    }
}

use crate::{
    id::NodeId,
    prover_trees::{piop_tree::ProverPIOPTree, proof_tree::ProverProofTree},
};
use std::sync::Arc;

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
pub struct AliasExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub node_id: NodeId,
    pub inputs: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for AliasExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn as_any(&self) -> &dyn std::any::Any {
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
        let alias = match expr.clone() {
            Expr::Alias(alias) => alias,
            _ => panic!("expected alias expression"),
        };
        let input_expr = (*alias.expr).clone();
        let child = ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
            ctx,
            prover_ctx,
            input_expr,
            &parent_logical_plan,
        );
        Self {
            node_id: NodeId::Expr(expr),
            inputs: vec![child],
        }
    }

    fn cost(&self, _statistics: Statistics, _schema: SchemaRef) -> ProvingCost {
        todo!()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
        if let Some(inner) = self.inputs.first() {
            if let Some(table) = piop_tree.table(&inner.node_id(), "output_plan") {
                piop_tree.add_table(
                    self.node_id.clone(),
                    "output_plan".to_string(),
                    table.clone(),
                );
            }
        }
    }
    fn prove_piop(
        &self,
        _prover: &mut Prover<F, MvPCS, UvPCS>,
        _piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        todo!()
    }
}

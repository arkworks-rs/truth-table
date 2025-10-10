// Combined dbsnark-core/src/prover/nodes/exprs/aggregate_function.rs and
// dbsnark-core/src/verifier/nodes/exprs/aggregate_function.rs

use crate::{
    prover::trees::{piop_tree::ProverPIOPTree, proof_tree::ProverProofTree},
};
use crate::proof_nodes::id::NodeId;
use arithmetic::{ctx::SharedCtx, table::TrackedTable};
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
use indexmap::IndexMap;
use std::{any::Any, sync::Arc};

use crate::proof_nodes::{cost::ProvingCost, prover::ProverNode, verifier::VerifierNode};
#[derive(Clone)]
pub struct ProverAggregateFunctionExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub node_id: NodeId,
    pub inputs: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS>
    for ProverAggregateFunctionExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{

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
        let mut collected_cols = IndexMap::new();
        let mut table_log_size: Option<usize> = None;

        for child in &self.inputs {
            let table = piop_tree
                .tracked_table(&child.node_id(), "output_plan")
                .unwrap_or_else(|| {
                    panic!(
                        "missing output_plan table for aggregate argument {}",
                        child.name()
                    )
                });

            let child_log_size = table.log_size();
            if let Some(expected) = table_log_size {
                assert_eq!(
                    expected, child_log_size,
                    "aggregate arguments must share the same table log size",
                );
            } else {
                table_log_size = Some(child_log_size);
            }
            let col = table.tracked_col_by_ind(0);
            let field = col.field_ref().unwrap();
            collected_cols.insert(field, col.data_tracked_poly().clone());
        }

        if collected_cols.is_empty() {
            return;
        }

        let output_table = TrackedTable::new(None, collected_cols, table_log_size.unwrap_or(0));
        piop_tree.add_table(
            self.node_id.clone(),
            "output_plan".to_string(),
            output_table,
        );
    }
    fn prove_piop(
        &self,
        _prover: &mut Prover<F, MvPCS, UvPCS>,
        _piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        todo!()
    }
}

#[derive(Clone)]
pub struct VerifierAggregateFunctionExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub relative_expr: Expr,
    pub output_expr: Expr,
    pub inputs: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS>
    for VerifierAggregateFunctionExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{

    fn node_id(&self) -> NodeId {
        NodeId::Expr(self.relative_expr.clone())
    }

    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        self.inputs.iter().collect()
    }

    fn from_expr(
        ctx: &datafusion::prelude::SessionContext,
        _verifier_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        parent_logical_plan: datafusion::logical_expr::LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        todo!()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }
    fn verify_piop(
        &self,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        todo!()
    }
}

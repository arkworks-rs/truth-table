use crate::{
    id::NodeId,
    prover::trees::{piop_tree::ProverPIOPTree, proof_tree::ProverProofTree},
};
use std::{any::Any, sync::Arc};

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

use crate::prover::nodes::{ProverNode, cost::ProvingCost};

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
        let mut collected_cols = Vec::new();
        let mut table_size: Option<usize> = None;

        for child in &self.inputs {
            let table = piop_tree
                .tracked_table(&child.node_id(), "output_plan")
                .unwrap_or_else(|| {
                    panic!(
                        "missing output_plan table for aggregate argument {}",
                        child.name()
                    )
                });

            let child_size = table.size();
            if let Some(expected) = table_size {
                assert_eq!(
                    expected, child_size,
                    "aggregate arguments must share the same table size",
                );
            } else {
                table_size = Some(child_size);
            }
            let col = table.col(0);
            let field = col
                .data_type()
                .map(|dt| {
                    datafusion::arrow::datatypes::FieldRef::new(
                        datafusion::arrow::datatypes::Field::new("arg", dt, true),
                    )
                })
                .unwrap_or_else(|| {
                    datafusion::arrow::datatypes::FieldRef::new(
                        datafusion::arrow::datatypes::Field::new(
                            "arg",
                            datafusion::arrow::datatypes::DataType::Null,
                            true,
                        ),
                    )
                });
            collected_cols.push((field, col.data_poly().clone()));
        }

        if collected_cols.is_empty() {
            return;
        }

        let output_table = TrackedTable::new(None, collected_cols, table_size.unwrap_or(0));
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

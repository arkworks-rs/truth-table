use crate::id::NodeId;
use std::sync::Arc;

use arithmetic::{ctx::SharedCtx, table::TrackedTable};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
};
use datafusion::{
    logical_expr::{Expr, LogicalPlan},
    prelude::SessionContext,
};
use indexmap::IndexMap;

use crate::prover::nodes::cost::ProvingCost;

use crate::prover::{nodes::ProverNode, trees::piop_tree::ProverPIOPTree};
use arithmetic::ACTIVATOR_COL_NAME;
#[derive(Clone)]
pub struct ColumnExprNode {
    pub parent_logical_plan: LogicalPlan,
    pub node_id: NodeId,
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for ColumnExprNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn from_expr(
        _ctx: &SessionContext,
        _prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        parent_logical_plan: LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        Self {
            node_id: NodeId::Expr(expr),
            parent_logical_plan,
        }
    }

    fn cost(
        &self,
        _statistics: datafusion::common::Statistics,
        _schema: datafusion::arrow::datatypes::SchemaRef,
    ) -> ProvingCost {
        todo!()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
        prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
        // Fetch the columns expression
        let column_expr = match &self.node_id {
            NodeId::Expr(Expr::Column(column)) => column,
            _ => todo!(),
        };
        // If the column has a table reference, then find the TableScan
        // that loads that table and use the column there. Otherwise, if it
        // doesn't have a table reference, it must be from the parent logical plan
        let parent_node_id = match column_expr.relation.as_ref() {
            Some(relation) => piop_tree
                .tracked_tables()
                .keys()
                .find(|node_id| match node_id {
                    NodeId::LP(LogicalPlan::TableScan(scan_plan)) => {
                        &scan_plan.table_name == relation
                    },
                    _ => false,
                })
                .unwrap(),
            None => &NodeId::LP(self.parent_logical_plan.clone()),
        };

        let table = piop_tree
            .tracked_table(parent_node_id, "output_plan")
            .expect("table not found in PIOP tree");
        let col = table
            .tracked_col_by_name(&column_expr.name)
            .expect("column not found in table");
        // TODO: Clean this up later
        let mut tracked_polys: IndexMap<
            Arc<datafusion::arrow::datatypes::Field>,
            ark_piop::prover::structs::polynomial::TrackedPoly<F, MvPCS, UvPCS>,
        > = IndexMap::from([(
            col.field_ref()
                .expect("Column data type should not be None")
                .clone(),
            col.data_tracked_poly().clone(),
        )]);
        tracked_polys.insert(
            Arc::new(datafusion::arrow::datatypes::Field::new(
                ACTIVATOR_COL_NAME,
                datafusion::arrow::datatypes::DataType::UInt8,
                true,
            )),
            col.activator_tracked_poly()
                .expect("Column activator polynomial should not be None")
                .clone(),
        );
        let output_table = TrackedTable::new(None, tracked_polys, 0);

        piop_tree.add_table(self.node_id.clone(), "output_plan".to_owned(), output_table);
    }
    fn prove_piop(
        &self,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

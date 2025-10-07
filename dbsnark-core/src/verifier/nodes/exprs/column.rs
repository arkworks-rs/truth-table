use crate::{id::NodeId, verifier::nodes::VerifierNode};
use std::sync::Arc;

use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS, verifier::structs::oracle::TrackedOracle,
};
use datafusion::{
    arrow::datatypes::FieldRef,
    logical_expr::{Expr, LogicalPlan},
    prelude::SessionContext,
};
use indexmap::IndexMap;

use crate::verifier::trees::piop_tree::VerifierPIOPTree;

#[derive(Clone)]
pub struct ColumnExprNode {
    pub parent_logical_plan: LogicalPlan,
    pub node_id: NodeId,
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for ColumnExprNode
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

    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn from_expr(
        _ctx: &SessionContext,
        _verifier_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        _parent_logical_plan: LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        Self {
            node_id: NodeId::Expr(expr),
            parent_logical_plan: _parent_logical_plan,
        }
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
        verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
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
                .tracked_table_oracles()
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
            .tracked_table_oracle(parent_node_id, "output_plan")
            .expect("table not found in PIOP tree");
        let col = table
            .col_by_name(&column_expr.name)
            .expect("column not found in table");
        let mut data_polys: IndexMap<FieldRef, TrackedOracle<F, MvPCS, UvPCS>> = IndexMap::new();
        let data_field: FieldRef = Arc::new(datafusion::arrow::datatypes::Field::new(
            column_expr.name.as_str(),
            col.data_type()
                .expect("Column data type should not be None")
                .clone(),
            true,
        ));
        data_polys.insert(data_field, col.data_oracle().clone());

        let activator_field: FieldRef = Arc::new(datafusion::arrow::datatypes::Field::new(
            "activator",
            datafusion::arrow::datatypes::DataType::UInt8,
            true,
        ));
        data_polys.insert(
            activator_field,
            col.actvtr_oracle()
                .expect("Column activator polynomial should not be None")
                .clone(),
        );

        let output_table = TrackedTableOracle::new(None, data_polys, 0);

        piop_tree.add_tracked_table_oracle(
            self.node_id.clone(),
            "output_plan".to_owned(),
            output_table,
        );
    }
    fn verify_piop(
        &self,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

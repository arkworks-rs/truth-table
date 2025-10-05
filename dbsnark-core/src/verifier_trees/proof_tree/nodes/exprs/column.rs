use crate::{id::NodeId, verifier_trees::proof_tree::nodes::VerifierNode};
use std::sync::Arc;

use arithmetic::table::TrackedTable;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
};
use datafusion::{
    arrow::datatypes::FieldRef,
    logical_expr::{Expr, LogicalPlan},
    prelude::SessionContext,
};

use crate::verifier_trees::piop_tree::VerifierPIOPTree;

#[derive(Clone)]
pub struct ColumnExprNode {
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
        }
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
        prover: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
        todo!()
        // let column_expr = match &self.node_id {
        //     NodeId::Expr(Expr::Column(column)) => column,
        //     _ => todo!(),
        // };
        // let relation = match column_expr.relation.as_ref() {
        //     Some(relation) => relation,
        //     None => todo!(),
        // };
        // let matching_table_scan = piop_tree.tables().keys().find(|node_id|
        // match node_id {
        //     NodeId::LP(LogicalPlan::TableScan(scan_plan)) =>
        // &scan_plan.table_name == relation,     _ => false,
        // });

        // let table_scan_node_id = matching_table_scan.expect("matching table
        // scan not found"); let table = piop_tree
        //     .table(table_scan_node_id, "output_plan")
        //     .expect("table not found in PIOP tree");
        // let col = table
        //     .col_by_name(&column_expr.name)
        //     .expect("column not found in table");
        // // TODO: Clean this up later
        // let mut data_polys: Vec<(
        //     Arc<datafusion::arrow::datatypes::Field>,
        //     ark_piop::prover::structs::polynomial::TrackedPoly<F, MvPCS,
        // UvPCS>, )> = vec![(
        //     Arc::new(datafusion::arrow::datatypes::Field::new(
        //         column_expr.name.as_str(),
        //         col.data_type()
        //             .expect("Column data type should not be None")
        //             .clone(),
        //         true,
        //     )),
        //     col.data_poly().clone(),
        // )]
        // .into_iter()
        // .collect();
        // data_polys.push((
        //     Arc::new(datafusion::arrow::datatypes::Field::new(
        //         "activator",
        //         datafusion::arrow::datatypes::DataType::UInt8,
        //         true,
        //     )),
        //     col.actvtr_poly()
        //         .expect("Column activator polynomial should not be None")
        //         .clone(),
        // ));
        // let output_table = TrackedTable::new(None, data_polys, 0);

        // piop_tree.add_table(self.node_id.clone(), "output_plan".to_owned(),
        // output_table);
    }
    fn verify_piop(
        &self,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::verifier_trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

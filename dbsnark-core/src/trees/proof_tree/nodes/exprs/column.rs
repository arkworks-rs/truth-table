use std::sync::Arc;

use arithmetic::table::ArithTable;
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

use crate::trees::{
    piop_tree::PIOPTree,
    proof_tree::nodes::{ProverNode, ProverNodeNodeId},
};

#[derive(Clone)]
pub struct ColumnExprNode {
    pub node_id: ProverNodeNodeId,
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

    fn node_id(&self) -> ProverNodeNodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn from_expr(
        _ctx: &SessionContext,
        _prover_ctx: arithmetic::ctx::ProverCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        _parent_logical_plan: LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        Self {
            node_id: ProverNodeNodeId::Expr(expr),
        }
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut PIOPTree<F, MvPCS, UvPCS>,
        prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
        let column_expr = match &self.node_id {
            ProverNodeNodeId::Expr(Expr::Column(column)) => column,
            _ => todo!(),
        };
        let relation = match column_expr.relation.as_ref() {
            Some(relation) => relation,
            None => todo!(),
        };
        let matching_table_scan = piop_tree.tables().keys().find(|node_id| match node_id {
            ProverNodeNodeId::LP(LogicalPlan::TableScan(scan_plan)) => {
                &scan_plan.table_name == relation
            },
            _ => false,
        });

        let table_scan_node_id = matching_table_scan.expect("matching table scan not found");
        let table = piop_tree
            .table(table_scan_node_id, "output_plan")
            .expect("table not found in PIOP tree");
        let col = table
            .col_by_name(&column_expr.name)
            .expect("column not found in table");
        // TODO: Clean this up later
        let mut data_polys: Vec<(
            Arc<datafusion::arrow::datatypes::Field>,
            ark_piop::prover::structs::polynomial::TrackedPoly<F, MvPCS, UvPCS>,
        )> = vec![(
            Arc::new(datafusion::arrow::datatypes::Field::new(
                column_expr.name.as_str(),
                col.data_type()
                    .expect("Column data type should not be None")
                    .clone(),
                true,
            )),
            col.data_poly().clone(),
        )]
        .into_iter()
        .collect();
        data_polys.push((
            Arc::new(datafusion::arrow::datatypes::Field::new(
                "activator",
                datafusion::arrow::datatypes::DataType::UInt8,
                true,
            )),
            col.actvtr_poly()
                .expect("Column activator polynomial should not be None")
                .clone(),
        ));
        let output_table = ArithTable::new(None, data_polys, 0);

        piop_tree.add_table(self.node_id.clone(), "output_plan".to_owned(), output_table);
    }
    fn prove_piop(
        &self,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::trees::piop_tree::PIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

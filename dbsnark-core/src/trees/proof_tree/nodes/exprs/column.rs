use std::sync::Arc;

use arithmetic::table::ArithTable;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{
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

    fn from_expr(_ctx: &SessionContext, expr: Expr, _parent_logical_plan: LogicalPlan) -> Self
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
        let output_table = ArithTable::new(
            None,
            vec![col.data_poly().clone()],
            col.actvtr_poly().cloned(),
            0,
        );

        piop_tree.add_table(self.node_id.clone(), "output_plan".to_owned(), output_table);
    }
}

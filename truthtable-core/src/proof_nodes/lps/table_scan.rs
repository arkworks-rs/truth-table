use std::sync::Arc;

use arithmetic::ctx::SharedCtx;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::prelude::SessionContext;
use datafusion_expr::{LogicalPlan, TableScan};

use crate::{
    proof_nodes::{
        HintDF,
        prover::{ProverLpNode, ProverPlanNode},
    },
    prover::trees::proof_tree::ProverProofTree,
    tree::NodeId,
};

pub struct ProverTableScanNode {
    pub table_scan: TableScan,
}
pub struct VerifierTableScanNode {
    pub table_scan: TableScan,
}

impl<F, MvPCS, UvPCS> ProverPlanNode<F, MvPCS, UvPCS> for ProverTableScanNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn node_id(&self) -> NodeId {
        NodeId::LP(LogicalPlan::TableScan(self.table_scan.clone()))
    }


    fn arithmetic_post_process(&self) {
        todo!()
    }

    fn add_virtual_witness(&self, prover: &mut ark_piop::prover::ArgProver<F, MvPCS, UvPCS>) {
        todo!()
    }


    fn cost(
        &self,
        statistics: datafusion::common::Statistics,
        schema: datafusion::arrow::datatypes::SchemaRef,
    ) -> crate::proof_nodes::cost::ProvingCost {
        todo!()
    }

    fn output(&self, proof_tree: &ProverProofTree<F, MvPCS, UvPCS>) -> HintDF {
        todo!()
    }

    fn ctx_lp_node(
        &self,
        proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>> {
        todo!()
    }

    fn children(&self) -> Vec<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>> {
        vec![]
    }
    
    fn gadget_tree(&self) -> crate::prover::trees::gadget_tree::GadgetTree<F, MvPCS, UvPCS> {
        todo!()
    }

}

impl<F, MvPCS, UvPCS> ProverLpNode<F, MvPCS, UvPCS> for ProverTableScanNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn from_lp(
        ctx: &SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        let table_scan = match plan {
            LogicalPlan::TableScan(table_scan) => table_scan,
            _ => panic!(
                "ProverTableScanNode can only be created from a TableScan logical plan. Parent node ID: {:?}",
                parent_node_id
            ),
        };
        Self { table_scan }
    }
}

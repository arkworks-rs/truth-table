use ark_piop::SnarkBackend;
use datafusion_expr::{LogicalPlan, TableScan};

use crate::irs::{
    nodes::id::{NodeId, PlanNodeId},
    tree::{Gadget, LpNode, Node, PlanNode},
};

mod gadget;
#[derive(Debug)]
pub struct ProverNode {
    pub table_scan: TableScan,
}

impl<B: SnarkBackend> Node<B> for ProverNode {
    fn id(&self) -> crate::irs::nodes::id::NodeId {
        NodeId::PLAN(PlanNodeId::LP(LogicalPlan::TableScan(
            self.table_scan.clone(),
        )))
    }

    fn cost(
        &self,
        statistics: datafusion_common::Statistics,
        schema: datafusion::arrow::datatypes::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn as_plan_node(&self) -> Option<&dyn PlanNode<B>> {
        Some(self)
    }

    fn as_gadget_node(&self) -> Option<&dyn Gadget<B>> {
        None
    }

    fn name(&self) -> String {
        "TableScan".to_string()
    }
}

impl<B: SnarkBackend> PlanNode<B> for ProverNode {
    fn children(&self) -> Vec<std::sync::Arc<dyn Node<B>>> {
        Vec::new()
    }

    fn gadget(&self) -> std::sync::Arc<dyn Gadget<B>> {
        todo!()
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        todo!()
    }
}

impl<B: SnarkBackend> LpNode<B> for ProverNode {
    fn from_lp(plan: datafusion_expr::LogicalPlan) -> Self
    where
        Self: Sized,
    {
        let table_scan = match plan {
            LogicalPlan::TableScan(table_scan) => table_scan,
            _ => panic!(),
        };
        Self { table_scan }
    }
}

// impl<B> ProverPlanNode<B> for ProverTableScanNode
// where
//     F: PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
// {
//     fn node_id(&self) -> NodeId {
//         NodeId::LP(LogicalPlan::TableScan(self.table_scan.clone()))
//     }

//     fn arithmetic_post_process(&self) {
//         todo!()
//     }

//     fn add_virtual_witness(&self, prover: &mut ark_piop::prover::ArgProver<B>) {
//         todo!()
//     }

//     fn cost(
//         &self,
//         statistics: datafusion::common::Statistics,
//         schema: datafusion::arrow::datatypes::SchemaRef,
//     ) -> crate::nodes::cost::ProvingCost {
//         todo!()
//     }

//     fn output(&self, proof_tree: &ProverProofTree<B>) -> HintDF {
//         todo!()
//     }

//     fn ctx_lp_node(
//         &self,
//         proof_tree: &ProverProofTree<B>,
//     ) -> Arc<dyn ProverPlanNode<B>> {
//         todo!()
//     }

//     fn children(&self) -> Vec<Arc<dyn ProverPlanNode<B>>> {
//         Vec::new()
//     }

//     fn gadget_tree(&self) -> crate::prover::trees::gadget_tree::GadgetTree<B> {
//         let root = gadget::Prover::new();
//         GadgetTree::new(Arc::new(root))
//     }
// }

// impl<B> ProverLpNode<B> for ProverTableScanNode
// where
//     F: PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
// {
//     fn from_lp(
//         ctx: &SessionContext,
//         prover_ctx: SharedCtx<B>,
//         plan: LogicalPlan,
//         parent_node_id: NodeId,
//     ) -> Self
//     where
//         Self: Sized,
//     {
//         let table_scan = match plan {
//             LogicalPlan::TableScan(table_scan) => table_scan,
//             _ => panic!(
//                 "ProverTableScanNode can only be created from a TableScan logical plan. Parent node ID: {:?}",
//                 parent_node_id
//             ),
//         };
//         Self { table_scan }
//     }
// }

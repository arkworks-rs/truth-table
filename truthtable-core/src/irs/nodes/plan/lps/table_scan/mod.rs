use ark_piop::SnarkBackend;
use datafusion_expr::TableScan;

use crate::irs::nodes::{IsLpNode, IsNode, IsPlanNode, Node};

mod gadget;
#[derive(Debug)]
pub struct ProverNode {
    table_scan: TableScan,
}

impl<B: SnarkBackend> IsNode<B> for ProverNode {
    fn name(&self) -> String {
        todo!()
    }

    fn cost(
        &self,
        statistics: datafusion_common::Statistics,
        schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn id(&self) -> crate::irs::nodes::NodeId {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        todo!()
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ProverNode {
    fn gadget(&self) -> std::sync::Arc<Node<B>> {
        todo!()
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        todo!()
    }
}

impl<B: SnarkBackend> IsLpNode<B> for ProverNode {
    fn from_lp(_plan: datafusion_expr::LogicalPlan, self_ref: std::sync::Weak<Node<B>>) -> Self
    where
        Self: Sized,
    {
        let table_scan = match _plan {
            datafusion_expr::LogicalPlan::TableScan(ts) => ts,
            _ => panic!("Expected TableScan logical plan"),
        };
        Self { table_scan }
    }

    fn lp(&self) -> datafusion_expr::LogicalPlan {
        todo!()
    }
}

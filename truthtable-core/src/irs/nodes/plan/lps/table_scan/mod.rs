use arithmetic::ACTIVATOR_COL_NAME;
use ark_piop::SnarkBackend;
use datafusion::prelude::SessionContext;
use datafusion_expr::TableScan;

use crate::irs::nodes::{IsLpNode, IsNode, IsPlanNode, Node};

mod gadget;
#[derive(Debug)]
pub struct ProverNode {
    table_scan: TableScan,
}

impl<B: SnarkBackend> IsNode<B> for ProverNode {
    fn name(&self) -> String {
        "TableScan".to_string()
    }

    fn cost(
        &self,
        statistics: datafusion_common::Statistics,
        schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![]
    }

    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ProverNode {
    fn gadget(&self) -> std::sync::Arc<Node<B>> {
        todo!()
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        use datafusion::dataframe::DataFrame;
        use datafusion_expr::lit;

        let ctx = SessionContext::new();
        let df = DataFrame::new(
            ctx.state(),
            datafusion_expr::LogicalPlan::TableScan(self.table_scan.clone()),
        )
        .with_column(ACTIVATOR_COL_NAME, lit(true))
        .expect("failed to append activator column to table scan output");

        crate::irs::nodes::hints::HintDF::new_materialized(df)
    }
}

impl<B: SnarkBackend> IsLpNode<B> for ProverNode {
    fn from_lp(_plan: datafusion_expr::LogicalPlan, _parent: std::sync::Weak<Node<B>>) -> Self
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

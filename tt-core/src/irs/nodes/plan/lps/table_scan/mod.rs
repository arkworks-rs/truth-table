use ark_piop::SnarkBackend;
use datafusion::prelude::SessionContext;
use datafusion_expr::TableScan;

use crate::irs::nodes::{IsLpNode, IsNode, IsPlanNode, Node, ProverNodeOps, VerifierNodeOps};

#[derive(Debug)]
pub struct LpNode {
    table_scan: TableScan,
}

impl<B: SnarkBackend> IsNode<B> for LpNode {
    fn name(&self) -> String {
        "TableScan".to_string()
    }

    fn display(&self) -> String {
        format!(
            "TableScan\nTable: {}, projection: {:?}, filters: {}, fetch: {:?}",
            self.table_scan.table_name,
            self.table_scan.projection,
            self.table_scan.filters.len(),
            self.table_scan.fetch
        )
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for LpNode {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for LpNode {
    fn gadget(&self) -> Option<Node<B>> {
        None
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsProverPlanNode<B> for LpNode {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        use datafusion::dataframe::DataFrame;
        use indexmap::IndexMap;

        let ctx = SessionContext::new();
        let df = DataFrame::new(
            ctx.state(),
            datafusion_expr::LogicalPlan::TableScan(self.table_scan.clone()),
        );
        let df = crate::irs::nodes::hints::sort_by_row_id_if_present(df)
            .expect("table scan row-id sort should succeed");
        let should_materialize: IndexMap<_, _> = df
            .schema()
            .fields()
            .iter()
            .map(|field| {
                let mat = field.name() != arithmetic::ROW_ID_COL_NAME;
                (field.clone(), mat)
            })
            .collect();
        crate::irs::nodes::hints::HintDF::new(df, should_materialize)
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for LpNode {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        use datafusion::dataframe::DataFrame;
        use datafusion_expr::{LogicalPlan, logical_plan::EmptyRelation};
        use indexmap::IndexMap;
        use std::sync::OnceLock;

        // Keep qualifier-aware DFSchema for verifier column resolution while staying schema-only.
        static VERIFIER_SCHEMA_CTX: OnceLock<SessionContext> = OnceLock::new();
        let ctx = crate::irs::nodes::hints::scoped_schema_only_ctx()
            .unwrap_or_else(|| VERIFIER_SCHEMA_CTX.get_or_init(SessionContext::new).clone());
        let df = DataFrame::new(
            ctx.state(),
            LogicalPlan::EmptyRelation(EmptyRelation {
                produce_one_row: false,
                schema: self.table_scan.projected_schema.clone(),
            }),
        );
        let should_materialize: IndexMap<_, _> = df
            .schema()
            .fields()
            .iter()
            .map(|field| {
                let mat = field.name() != arithmetic::ROW_ID_COL_NAME;
                (field.clone(), mat)
            })
            .collect();
        crate::irs::nodes::hints::HintDF::new(df, should_materialize)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for LpNode {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsLpNode<B> for LpNode {
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
        datafusion_expr::LogicalPlan::TableScan(self.table_scan.clone())
    }
}

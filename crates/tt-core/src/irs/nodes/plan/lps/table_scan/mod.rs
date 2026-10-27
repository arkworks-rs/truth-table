use std::any::Any;
use std::collections::HashSet;
use std::sync::Mutex;

use crate::session::session_context;
use arithmetic::encoding::STRING_RANK_SUFFIX;
use arithmetic::table::TrackedTable;
use arithmetic::table_oracle::TrackedTableOracle;
use ark_piop::{SnarkBackend, types::TrackerID};
use datafusion::arrow::datatypes::Schema;
use datafusion::prelude::SessionContext;
use datafusion_expr::TableScan;
use indexmap::IndexMap;

use crate::irs::nodes::{
    IsLpNode, IsNode, IsPlanNode, Node, PlanNode, ProverNodeOps, VerifierNodeOps,
};
use crate::irs::payloads::PayloadStructure;

#[derive(Debug)]
pub struct LpNode {
    table_scan: TableScan,
    /// The rank segment of each ranked column, as `(id, num_vars)`, which
    /// `add_virtual_witness` takes out of the scan's payload on either side.
    /// Tracked handles are not `Send`, so a consumer rebuilds one with
    /// `TrackedPoly::new(Either::Left(id), num_vars, tracker)` or
    /// `TrackedOracle::new(Either::Left(id), tracker, num_vars)`, taking the
    /// tracker from its own payload.
    rank_polys: Mutex<IndexMap<String, (TrackerID, usize)>>,
}

impl LpNode {
    pub fn of<B: SnarkBackend>(node: &Node<B>) -> Option<&Self> {
        let Node::Plan(PlanNode::LpBased(lp_node)) = node else {
            return None;
        };
        (lp_node.as_ref() as &dyn Any).downcast_ref::<Self>()
    }

    /// The rank segment of `column` that this scan carried; available from
    /// the virtualization pass on.
    pub fn rank_poly(&self, column: &str) -> Option<(TrackerID, usize)> {
        self.rank_polys
            .lock()
            .expect("rank cache poisoned")
            .get(column)
            .copied()
    }
}

fn schema_without(schema: Option<&Schema>, dropped: &HashSet<String>) -> Option<Schema> {
    schema.map(|schema| {
        let fields: Vec<_> = schema
            .fields()
            .iter()
            .filter(|field| !dropped.contains(field.name()))
            .cloned()
            .collect();
        Schema::new_with_metadata(fields, schema.metadata().clone())
    })
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
    /// A rank is read only through [`LpNode::rank_poly`]: no operator binds
    /// it, so it must not reach a join key, an equality fold or a
    /// compaction above the scan. Mirrored by the verifier.
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let mut ranks = IndexMap::new();
        if let Some(PayloadStructure::PlanPayload(table)) = virtualized_ir.payload_for_node(&id) {
            let mut rank_fields = HashSet::new();
            for (field, col) in table.tracked_cols_iter() {
                if let Some(rank) = col.aux_segment(STRING_RANK_SUFFIX) {
                    ranks.insert(field.name().clone(), (rank.data.id(), rank.data.log_size()));
                    rank_fields.insert(format!("{}{STRING_RANK_SUFFIX}", field.name()));
                }
            }
            if !rank_fields.is_empty() {
                let polys = table
                    .tracked_polys()
                    .into_iter()
                    .filter(|(field, _)| !rank_fields.contains(field.name()))
                    .collect();
                let stripped = TrackedTable::new_with_side_cols(
                    schema_without(table.schema_ref(), &rank_fields),
                    polys,
                    table.log_size(),
                    table.side_cols(),
                );
                virtualized_ir
                    .set_payload_for_node(id, Some(PayloadStructure::PlanPayload(stripped)));
            }
        }
        *self.rank_polys.lock().expect("rank cache poisoned") = ranks;
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
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
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

        let ctx = session_context();
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
        use datafusion_expr::lit;
        use datafusion_expr::{LogicalPlan, logical_plan::EmptyRelation};
        use indexmap::IndexMap;
        use std::sync::OnceLock;

        // Keep qualifier-aware DFSchema for verifier column resolution while staying schema-only.
        static VERIFIER_SCHEMA_CTX: OnceLock<SessionContext> = OnceLock::new();
        let ctx = crate::irs::nodes::hints::scoped_schema_only_ctx()
            .unwrap_or_else(|| VERIFIER_SCHEMA_CTX.get_or_init(session_context).clone());
        let mut df = DataFrame::new(
            ctx.state(),
            LogicalPlan::EmptyRelation(EmptyRelation {
                produce_one_row: false,
                schema: self.table_scan.projected_schema.clone(),
            }),
        );
        let source_schema = self.table_scan.source.schema();
        // DataFusion may prune our system columns out of `projected_schema`,
        // but verifier-side planning still needs to see them in schema-only
        // mode so downstream gadgets stay shape-aligned.
        let source_has_row_id = source_schema
            .fields()
            .iter()
            .any(|field| field.name() == arithmetic::ROW_ID_COL_NAME);
        let output_has_row_id = df
            .schema()
            .fields()
            .iter()
            .any(|field| field.name() == arithmetic::ROW_ID_COL_NAME);
        if source_has_row_id && !output_has_row_id {
            df = df
                .with_column(arithmetic::ROW_ID_COL_NAME, lit(0_i64))
                .expect("table scan verifier row-id restoration should succeed");
        }
        let source_has_activator = source_schema
            .fields()
            .iter()
            .any(|field| field.name() == arithmetic::ACTIVATOR_COL_NAME);
        let output_has_activator = df
            .schema()
            .fields()
            .iter()
            .any(|field| field.name() == arithmetic::ACTIVATOR_COL_NAME);
        if source_has_activator && !output_has_activator {
            df = df
                .with_column(arithmetic::ACTIVATOR_COL_NAME, lit(true))
                .expect("table scan verifier activator restoration should succeed");
        }
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
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let mut ranks = IndexMap::new();
        if let Some(PayloadStructure::PlanPayload(table)) = virtualized_ir.payload_for_node(&id) {
            let mut rank_fields = HashSet::new();
            for (field, col) in table.tracked_col_oracles_iter() {
                if let Some(rank) = col.aux_segment(STRING_RANK_SUFFIX) {
                    ranks.insert(field.name().clone(), (rank.data.id(), rank.data.log_size()));
                    rank_fields.insert(format!("{}{STRING_RANK_SUFFIX}", field.name()));
                }
            }
            if !rank_fields.is_empty() {
                let oracles = table
                    .tracked_oracles()
                    .into_iter()
                    .filter(|(field, _)| !rank_fields.contains(field.name()))
                    .collect();
                let stripped = TrackedTableOracle::new_with_side_cols(
                    schema_without(table.schema_ref(), &rank_fields),
                    oracles,
                    table.log_size(),
                    table.side_cols(),
                );
                virtualized_ir
                    .set_payload_for_node(id, Some(PayloadStructure::PlanPayload(stripped)));
            }
        }
        *self.rank_polys.lock().expect("rank cache poisoned") = ranks;
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
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
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
        Self {
            table_scan,
            rank_polys: Mutex::new(IndexMap::new()),
        }
    }

    fn lp(&self) -> datafusion_expr::LogicalPlan {
        datafusion_expr::LogicalPlan::TableScan(self.table_scan.clone())
    }
}

#[cfg(test)]
mod tests;

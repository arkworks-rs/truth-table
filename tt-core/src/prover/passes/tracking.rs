use ark_piop::{SnarkBackend, prover::ArgProver};
use datafusion::arrow::datatypes::{Field, Schema};
use datafusion::{
    datasource::{MemTable, TableProvider},
    prelude::SessionContext,
};
use datafusion_common::DataFusionError;

use crate::irs::nodes::IsNode;
use crate::{
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
    },
    prover::{
        irs::TrackedIr,
        passes::arithmetization::arithmetize_materialized_table,
        passes::materialization::{
            append_activator_and_pad_batches, pad_batches_to_num_rows_with_inactive_padding,
        },
        payloads::{ArithPayload, CommittedPayload, MaterializedTable, TrackedPayload},
    },
};
use arithmetic::table::TrackedTable;
use arithmetic::table_oracle::ArithTableOracle;
use indexmap::IndexMap;
use std::{
    cell::{Cell, RefCell},
    sync::Arc,
};
use tracing::{debug, info};
/// A tracking pass that tracks the prover's arithmetized tables using commitments.
///
/// This pass converts an IR with committed table oracles into an IR with tracked tables; i.e.
/// tables that are tracked by the SNARK prover with an associated id. Commitments are supplied
/// by the commitment pass, so this pass stays sequential and only tracks.
pub struct TrackingPass<'a, B: SnarkBackend> {
    prover: RefCell<ArgProver<B>>,
    total_committed: Cell<usize>, // Track committed polynomial count across the entire pass.
    arith_payloads: &'a IndexMap<NodeId, Option<ArithPayload<B::F>>>,
    output_memtable: Option<Arc<MemTable>>,
}

impl<'a, B: SnarkBackend> TrackingPass<'a, B> {
    pub fn new(
        prover: ArgProver<B>,
        arith_payloads: &'a IndexMap<NodeId, Option<ArithPayload<B::F>>>,
        output_memtable: Option<Arc<MemTable>>,
    ) -> Self {
        Self {
            prover: RefCell::new(prover),
            total_committed: Cell::new(0),
            arith_payloads,
            output_memtable,
        }
    }

    pub async fn finish(&self, tracked_ir: &mut TrackedIr<B>) -> crate::errors::TTResult<()> {
        let Some(output_memtable) = self.output_memtable.clone() else {
            return Ok(());
        };
        let root = tracked_ir.tree().root();
        if root.name() != "ResultCheck" {
            return Ok(());
        }

        let output_memtable = Self::normalize_output_memtable(output_memtable).await?;
        let materialized = Self::materialized_table_from_memtable(output_memtable, None).await?;
        let arith_table = arithmetize_materialized_table::<B::F>(&materialized);
        let tracked_table = Self::track_arith_table_without_commitment(&arith_table, &self.prover)?;
        let gadget_id = root
            .children()
            .into_iter()
            .find(|child| child.name() == "ResultCheck")
            .map(|child| child.id())
            .ok_or_else(|| {
                DataFusionError::Internal("ResultCheck root missing gadget child".to_string())
            })?;
        let mut gadget_payload = match tracked_ir.payload_for_node(&gadget_id) {
            Some(crate::irs::payloads::PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(
            crate::irs::nodes::gadget::utils::result_check::OUTPUT_LABEL.to_string(),
            tracked_table,
        );
        tracked_ir.set_payload_for_node(
            gadget_id,
            Some(crate::irs::payloads::PayloadStructure::GadgetPayload(
                gadget_payload,
            )),
        );
        Ok(())
    }

    async fn materialized_table_from_memtable(
        mem_table: Arc<MemTable>,
        target_num_rows: Option<usize>,
    ) -> crate::errors::TTResult<MaterializedTable> {
        let ctx = SessionContext::new();
        let df = ctx.read_table(mem_table.clone())?;
        let mut batches = df.collect().await?;
        let schema = mem_table.schema();
        batches = pad_batches_to_num_rows_with_inactive_padding(
            schema.as_ref(),
            batches,
            target_num_rows,
        )?;
        let row_count = batches.iter().map(|batch| batch.num_rows()).sum();
        let rebuilt = MemTable::try_new(mem_table.schema(), vec![batches.clone()])
            .expect("memtable rebuild from collected batches should succeed");
        Ok(MaterializedTable::new_with_batches(
            rebuilt, row_count, batches,
        ))
    }

    async fn normalize_output_memtable(
        mem_table: Arc<MemTable>,
    ) -> crate::errors::TTResult<Arc<MemTable>> {
        let ctx = SessionContext::new();
        let df = ctx.read_table(mem_table.clone())?;
        let batches = df.collect().await?;
        let base_schema = batches
            .first()
            .map(|batch| batch.schema().as_ref().clone())
            .unwrap_or_else(|| mem_table.schema().as_ref().clone());
        let (output_schema, output_batches) =
            append_activator_and_pad_batches(&base_schema, batches)?;
        let normalized = MemTable::try_new(Arc::new(output_schema), vec![output_batches])?;
        Ok(Arc::new(normalized))
    }

    fn track_arith_table_without_commitment(
        arith_table: &arithmetic::table::ArithTable<B::F>,
        prover: &RefCell<ArgProver<B>>,
    ) -> crate::errors::TTResult<TrackedTable<B>> {
        let tracked_polys = arith_table
            .polynomials()
            .iter()
            .map(|(field_ref, mle)| {
                Ok((
                    field_ref.clone(),
                    prover.borrow_mut().track_mat_mv_poly(mle.as_ref().clone()),
                ))
            })
            .collect::<ark_piop::errors::SnarkResult<_>>()?;
        Ok(TrackedTable::new(
            arith_table.schema(),
            tracked_polys,
            arith_table.log_size(),
        ))
    }
}

impl<'a, B: SnarkBackend> Drop for TrackingPass<'a, B> {
    fn drop(&mut self) {
        info!(
            committed = self.total_committed.get(),
            "total tracked polynomials after tracking pass"
        );
    }
}

impl<'a, B> LocalPass<B, CommittedPayload<B>, TrackedPayload<B>> for TrackingPass<'a, B>
where
    B: SnarkBackend,
{
    fn order(&self) -> crate::irs::ir::PassOrder {
        crate::irs::ir::PassOrder::PostOrder
    }
    fn transform(
        &self,
        node: &Node<B>,
        id: NodeId,
        payload: Option<&CommittedPayload<B>>,
    ) -> Option<TrackedPayload<B>> {
        let arith_payload = self.arith_payloads.get(&id).and_then(|p| p.as_ref())?;
        match (payload?, arith_payload) {
            (CommittedPayload::PlanPayload(oracle), ArithPayload::PlanPayload(arith_table)) => {
                if arith_table.polynomials().is_empty() {
                    return None;
                }
                Some(TrackedPayload::PlanPayload(
                    arith_to_tracked_with_commitment(
                        arith_table,
                        oracle,
                        &self.prover,
                        &self.total_committed,
                        oracle.is_external_commitment_source(),
                    ),
                ))
            }
            (
                CommittedPayload::GadgetPayload(commit_map),
                ArithPayload::GadgetPayload(arith_map),
            ) => {
                let mut out = IndexMap::new();
                for (key, oracle) in commit_map {
                    let arith_table = arith_map
                        .get(key)
                        .expect("commitment payload missing arith table entry");
                    if arith_table.polynomials().is_empty() {
                        continue;
                    }
                    out.insert(
                        key.clone(),
                        arith_to_tracked_with_commitment(
                            arith_table,
                            oracle,
                            &self.prover,
                            &self.total_committed,
                            false,
                        ),
                    );
                }

                if out.is_empty() {
                    None
                } else {
                    Some(TrackedPayload::GadgetPayload(out))
                }
            }
            _ => {
                debug!(
                    node = node.name(),
                    "tracking pass payload mismatch for node"
                );
                None
            }
        }
    }

    fn name(&self) -> &'static str {
        "Prover Tracking"
    }
}

fn arith_to_tracked_with_commitment<B: SnarkBackend>(
    arith_table: &arithmetic::table::ArithTable<B::F>,
    oracle: &ArithTableOracle<B>,
    prover: &RefCell<ArgProver<B>>,
    total_committed: &Cell<usize>,
    external_commitments: bool,
) -> TrackedTable<B> {
    debug!(
        poly_count = arith_table.polynomials().len(),
        log_size = arith_table.log_size(),
        "tracking arithmetized polynomials with commitments"
    );
    let mut tracked_polys = IndexMap::with_capacity(arith_table.polynomials().len());
    let mut prover = prover.borrow_mut();
    for (field_ref, mle_arc) in arith_table.polynomials() {
        let commitment = oracle
            .comitments()
            .get(field_ref)
            .expect("commitment oracle missing field")
            .clone();
        // TableScan can reuse commitments from ctx_oracles; those commitments
        // must remain trackable but should not be counted as proof-emitted PCS
        // commitments.
        let tracked_poly = if external_commitments {
            prover
                .track_mat_mv_poly_with_external_commitment(mle_arc, commitment)
                .expect("failed to track polynomial with external commitment")
        } else {
            prover
                .track_mat_mv_poly_with_commitment(mle_arc, commitment)
                .expect("failed to track polynomial with commitment")
        };
        tracked_polys.insert(field_ref.clone(), tracked_poly);
        if !external_commitments {
            total_committed.set(total_committed.get() + 1);
        }
    }

    debug_assert_eq!(
        arith_table.log_size(),
        oracle.log_size(),
        "commitment oracle log_size should match arith table"
    );
    let schema = tracked_schema_with_oracle_metadata(
        arith_table.schema(),
        oracle.schema_ref(),
        tracked_polys.keys().map(|f| f.as_ref().clone()).collect(),
    );
    TrackedTable::new(schema, tracked_polys, arith_table.log_size())
}

fn tracked_schema_with_oracle_metadata(
    arith_schema: Option<Schema>,
    oracle_schema: Option<&Schema>,
    tracked_fields: Vec<Field>,
) -> Option<Schema> {
    if arith_schema.is_none() && oracle_schema.is_none() {
        return None;
    }

    // Keep field ordering exactly aligned with tracked_polys keys, while merging
    // table-level metadata from arith + oracle schemas (oracle takes precedence).
    let mut metadata = arith_schema
        .as_ref()
        .map(|s| s.metadata().clone())
        .unwrap_or_default();
    if let Some(schema) = oracle_schema {
        metadata.extend(schema.metadata().clone());
    }
    Some(Schema::new_with_metadata(tracked_fields, metadata))
}

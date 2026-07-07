use ark_ff::PrimeField;
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    prover::ArgProver,
    types::CommitmentBinding,
};
use datafusion::arrow::datatypes::{Field, FieldRef, Schema};
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

/// Lift the byte buffer of a side-col data poly into a transient
/// `MLE<F>`. The returned Arc should be dropped as soon as the call
/// consuming it returns so the F-form does not persist past the
/// operation that needs it.
fn materialize_side_data_mle<F: PrimeField>(
    bytes: &[u8],
    log_size: usize,
) -> Arc<MLE<F>> {
    debug_assert_eq!(bytes.len(), 1usize << log_size);
    let evals: Vec<F> = bytes.iter().map(|&b| F::from(b as u64)).collect();
    Arc::new(MLE::from_evaluations_vec(log_size, evals))
}

/// Build the contiguous-one activator MLE for a side col from its
/// `active_len`. Drop-promptly contract identical to
/// `materialize_side_data_mle`.
fn materialize_side_activator_mle<F: PrimeField>(
    log_size: usize,
    active_len: usize,
) -> Arc<MLE<F>> {
    let size = 1usize << log_size;
    debug_assert!(active_len <= size);
    let mut evals = vec![F::zero(); size];
    for slot in evals.iter_mut().take(active_len) {
        *slot = F::one();
    }
    Arc::new(MLE::from_evaluations_vec(log_size, evals))
}

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
            crate::irs::nodes::utils::result_check::OUTPUT_LABEL.to_string(),
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
        side_count = arith_table.side_cols().len(),
        log_size = arith_table.log_size(),
        "tracking arithmetized polynomials with commitments"
    );
    let mut tracked_polys = IndexMap::with_capacity(arith_table.polynomials().len());
    let mut prover_borrow = prover.borrow_mut();
    for (field_ref, mle_arc) in arith_table.polynomials() {
        let commitment = oracle
            .commitments()
            .get(field_ref)
            .expect("commitment oracle missing field")
            .clone();
        // TableScan can reuse commitments from ctx_oracles; those commitments
        // must remain trackable but should not be counted as proof-emitted PCS
        // commitments.
        let binding = if external_commitments {
            CommitmentBinding::External
        } else {
            CommitmentBinding::ProofEmitted
        };
        let tracked_poly = prover_borrow
            .track_mat_mv_poly_with_commitment(mle_arc, commitment, binding)
            .expect("failed to track polynomial with commitment");
        tracked_polys.insert(field_ref.clone(), tracked_poly);
        if !external_commitments {
            total_committed.set(total_committed.get() + 1);
        }
    }

    // Side-domain columns: each side col contributes (data, activator) tracked
    // polys. Side commitments are always freshly emitted by the prover (even
    // when the row-domain side came from a cached ctx oracle) so they bind as
    // `ProofEmitted` regardless of `external_commitments`.
    let mut tracked_side_cols: IndexMap<FieldRef, arithmetic::table::TrackedSideCol<B>> =
        IndexMap::with_capacity(arith_table.side_cols().len());
    for (field_ref, side) in arith_table.side_cols() {
        let side_oracle = oracle
            .side_commitments()
            .get(field_ref)
            .expect("commitment oracle missing side col entry");
        // Materialize transient MLEs from raw bytes / active_len so the
        // tracker can clone its own Arc. The local handles drop at the end
        // of the loop body; the tracker keeps its clones for the proof
        // lifetime.
        let data_mle = materialize_side_data_mle::<B::F>(&side.data, side.log_size);
        let data_poly = prover_borrow
            .track_mat_mv_poly_with_commitment(
                &data_mle,
                side_oracle.data.clone(),
                CommitmentBinding::ProofEmitted,
            )
            .expect("failed to track side data polynomial with commitment");
        let act_mle =
            materialize_side_activator_mle::<B::F>(side.log_size, side.active_len);
        let activator_poly = prover_borrow
            .track_mat_mv_poly_with_commitment(
                &act_mle,
                side_oracle.activator.clone(),
                CommitmentBinding::ProofEmitted,
            )
            .expect("failed to track side activator polynomial with commitment");
        drop(data_mle);
        drop(act_mle);
        total_committed.set(total_committed.get() + 2);
        tracked_side_cols.insert(
            field_ref.clone(),
            arithmetic::table::TrackedSideCol {
                data: data_poly,
                activator: activator_poly,
                log_size: side.log_size,
                active_len: side.active_len,
            },
        );
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
    TrackedTable::new_with_side_cols(
        schema,
        tracked_polys,
        arith_table.log_size(),
        tracked_side_cols,
    )
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

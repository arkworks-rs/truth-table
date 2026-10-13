use crate::session::session_context;
use ark_ff::PrimeField;
use ark_piop::{
    SnarkBackend, arithmetic::mat_poly::mle::MLE, prover::ArgProver, types::CommitmentBinding,
};
use datafusion::arrow::datatypes::{Field, FieldRef, Schema};
use datafusion::datasource::{MemTable, TableProvider};
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

/// A side-col data MLE in its native storage (`MLEStorage::U8` or `U32`),
/// 32× and 8× smaller than field elements.
fn materialize_side_data_mle<F: PrimeField>(
    data: &arithmetic::encoding::SideColData,
    log_size: usize,
) -> Arc<MLE<F>> {
    debug_assert_eq!(data.len(), 1usize << log_size);
    let mle = match data {
        arithmetic::encoding::SideColData::Bytes(bytes) => {
            MLE::<F>::from_u8s(bytes.clone(), log_size)
        }
        arithmetic::encoding::SideColData::U32(vals) => MLE::<F>::from_u32s(vals.clone(), log_size),
    };
    Arc::new(mle)
}

/// Tracks the arithmetized tables in the prover under the commitments the
/// commitment pass supplies. It only tracks, so it stays sequential.
pub struct TrackingPass<'a, B: SnarkBackend> {
    prover: RefCell<ArgProver<B>>,
    total_committed: Cell<usize>,
    arith_payloads: &'a IndexMap<NodeId, Option<ArithPayload<B::F>>>,
    output_memtable: Option<Arc<MemTable>>,
    /// One multiproof per table-scan column whose fingerprint bins this
    /// proof opens, in tracking order (see [`FingerprintOpenings`]).
    fingerprint_openings: RefCell<FingerprintOpenings>,
}

/// The Merkle multiproofs opening the fingerprint bins a proof tests, one
/// per (table scan, column) in the order both sides track them.
pub type FingerprintOpenings = Vec<Vec<arithmetic::fingerprint::merkle::Hash>>;

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
            fingerprint_openings: RefCell::new(Vec::new()),
        }
    }

    pub fn take_fingerprint_openings(&self) -> FingerprintOpenings {
        self.fingerprint_openings.take()
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
        // The final output table has no side segments: no PIOP reads them.
        let arith_table = arithmetize_materialized_table::<B::F>(&materialized, None, None);
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
        let ctx = session_context();
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
        let ctx = session_context();
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
                        &self.fingerprint_openings,
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
                            &self.fingerprint_openings,
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
    fingerprint_openings: &RefCell<FingerprintOpenings>,
) -> TrackedTable<B> {
    debug!(
        poly_count = arith_table.polynomials().len(),
        side_count = arith_table.side_cols().len(),
        log_size = arith_table.log_size(),
        "tracking arithmetized polynomials with commitments"
    );
    let mut tracked_polys = IndexMap::with_capacity(arith_table.polynomials().len());
    let mut prover_borrow = prover.borrow_mut();
    // Fingerprint bins opened per column, in tracking order.
    let mut opened: IndexMap<&str, Vec<usize>> = IndexMap::new();
    for (field_ref, mle_arc) in arith_table.polynomials() {
        // A table scan reuses commitments from ctx_oracles: they are tracked
        // but do not count as proof-emitted.
        let mut binding = if external_commitments {
            CommitmentBinding::External
        } else {
            CommitmentBinding::ProofEmitted
        };
        let commitment = match oracle.commitments().get(field_ref) {
            Some(commitment) => commitment.clone(),
            // A fingerprint bin the oracle seals under its column's root: the
            // proof carries its commitment, opened against the root.
            None => {
                let (column, bin) = arithmetic::encoding::fingerprint_limb_of(field_ref.name())
                    .expect("commitment oracle missing field");
                let commitment = oracle
                    .fingerprint_bin(column, bin)
                    .expect("oracle holds no bins for a fingerprint column (missing .bins file?)")
                    .clone();
                opened.entry(column).or_default().push(bin);
                binding = CommitmentBinding::ProofEmitted;
                commitment
            }
        };
        // ark-piop's tracker compresses the poly before storing it.
        let tracked_poly = prover_borrow
            .track_mat_mv_poly_with_commitment(mle_arc, commitment, binding)
            .expect("failed to track polynomial with commitment");
        tracked_polys.insert(field_ref.clone(), tracked_poly);
        if binding == CommitmentBinding::ProofEmitted {
            total_committed.set(total_committed.get() + 1);
        }
    }
    for (column, bins) in opened {
        let siblings = oracle
            .open_fingerprint_bins(column, &bins)
            .expect("opened bins are the oracle's");
        fingerprint_openings.borrow_mut().push(siblings);
    }

    // Each side col gives a (data, activator) pair of tracked polys. The
    // prover always emits the side commitments itself, even when the
    // row-domain ones come from a ctx oracle, so they bind as `ProofEmitted`.
    let mut tracked_side_cols: IndexMap<FieldRef, arithmetic::col::PolyBundle<B>> =
        IndexMap::with_capacity(arith_table.side_cols().len());
    for (field_ref, side) in arith_table.side_cols() {
        let side_oracle = oracle
            .side_commitments()
            .get(field_ref)
            .expect("commitment oracle missing side col entry");
        // The tracker keeps its own Arc clones of these MLEs.
        let data_mle = materialize_side_data_mle::<B::F>(&side.data, side.log_size);
        let data_poly = prover_borrow
            .track_mat_mv_poly_with_commitment(
                &data_mle,
                side_oracle.data.clone(),
                CommitmentBinding::ProofEmitted,
            )
            .expect("failed to track side data polynomial with commitment");
        let act_mle = Arc::new(MLE::<B::F>::from_prefix_activator(
            side.active_len,
            side.log_size,
        ));
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
            arithmetic::col::PolyBundle::new(data_poly, Some(activator_poly)),
        );
    }

    debug_assert_eq!(
        arith_table.log_size(),
        oracle.log_size(),
        "commitment oracle log_size should match arith table"
    );
    // The schema lists the row-domain fields in the table's regrouped order.
    // `arith_table.polynomials()` can put a column's aux segments after other
    // primary columns (`[primary_A, primary_B, aux_A_len, aux_B_len]`), but
    // `TrackedTable` groups each aux under its primary, the verifier's
    // `TrackedTableOracle::from_tracked_table` walks that order, and
    // `TrackedTableOracle::check_new_args` rejects a schema in another one.
    let table = TrackedTable::new_with_side_cols(
        None,
        tracked_polys,
        arith_table.log_size(),
        tracked_side_cols,
    );
    let post_regroup_fields: Vec<Field> = table
        .tracked_polys()
        .keys()
        .map(|f| f.as_ref().clone())
        .collect();
    let schema = tracked_schema_with_oracle_metadata(
        arith_table.schema(),
        oracle.schema_ref(),
        post_regroup_fields,
    );
    let mut table = table;
    table.set_schema(schema);
    table
}

fn tracked_schema_with_oracle_metadata(
    arith_schema: Option<Schema>,
    oracle_schema: Option<&Schema>,
    tracked_fields: Vec<Field>,
) -> Option<Schema> {
    if arith_schema.is_none() && oracle_schema.is_none() {
        return None;
    }

    // Fields follow the tracked_polys keys. Table metadata is merged from
    // both schemas, the oracle's taking precedence.
    let mut metadata = arith_schema
        .as_ref()
        .map(|s| s.metadata().clone())
        .unwrap_or_default();
    if let Some(schema) = oracle_schema {
        metadata.extend(schema.metadata().clone());
    }
    Some(Schema::new_with_metadata(tracked_fields, metadata))
}

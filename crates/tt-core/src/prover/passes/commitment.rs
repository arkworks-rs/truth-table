use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use arithmetic::table_oracle::ArithTableOracle;
use ark_ff::PrimeField;
use ark_piop::{
    SnarkBackend,
    arithmetic::{mat_poly::digest::mle_digest, mat_poly::mle::MLE},
    pcs::PCS,
};
use datafusion::arrow::datatypes::Schema;
use indexmap::IndexMap;
use serde_json::{Value, json};
use tracing::{debug, info};

/// Build a side-col data `MLE<F>` that keeps the native small-scalar storage.
///
/// The returned MLE uses `MLEStorage::U8` for byte columns and `MLEStorage::U32`
/// for u32 columns — 32× and 8× smaller than the equivalent field-element
/// representation. The storage survives across the tracker's Arc clone and the
/// PCS commit (which materializes transiently for MSM only).
fn materialize_side_data_mle<F: PrimeField>(
    data: &arithmetic::encoding::SideColData,
    log_size: usize,
) -> Arc<MLE<F>> {
    debug_assert_eq!(data.len(), 1usize << log_size);
    let mle = match data {
        arithmetic::encoding::SideColData::Bytes(bytes) => {
            MLE::<F>::from_u8s(bytes.clone(), log_size)
        }
        arithmetic::encoding::SideColData::U32(vals) => {
            MLE::<F>::from_u32s(vals.clone(), log_size)
        }
    };
    Arc::new(mle)
}

/// Build the contiguous-one activator MLE for a side col as bit-packed
/// storage. `MLEStorage::Bit` gives a 256× reduction over the field-element
/// form for a mask of arbitrary size.
fn materialize_side_activator_mle<F: PrimeField>(
    log_size: usize,
    active_len: usize,
) -> Arc<MLE<F>> {
    Arc::new(MLE::<F>::from_prefix_activator(active_len, log_size))
}

use crate::ctx_oracles::CtxOracles;
use crate::irs::ir::LocalPass;
use crate::irs::nodes::{IsNode, Node, NodeId};
use crate::prover::payloads::{ArithPayload, CommittedPayload};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Commitment cache keyed by the BLAKE3 digest of an MLE's evaluations.
/// Enables reuse of MSM results for identical polynomials across nodes.
type CommitmentCache<B> = Mutex<
    BTreeMap<[u8; 32], <<B as SnarkBackend>::MvPCS as PCS<<B as SnarkBackend>::F>>::Commitment>,
>;

/// A commitment pass that turns arithmetized tables into table oracles.
///
/// This pass commits to each arithmetized column and records only the resulting
/// commitments inside an `ArithTableOracle`, enabling parallel commitment.
pub struct CommitmentPass<B: SnarkBackend> {
    mv_pcs_param: Arc<<B::MvPCS as PCS<B::F>>::ProverParam>,
    ctx_oracles: CtxOracles<B>,
    allow_table_scan_commit_without_ctx: bool,
    total_committed: AtomicUsize, // Count polynomials committed by this pass.
    total_ctx_loaded: AtomicUsize, // Count polynomials loaded from ctx oracles.
    /// Cache from BLAKE3 digest of MLE evaluations to commitment, so identical
    /// polynomials across different nodes reuse the same MSM result.
    commitment_cache: CommitmentCache<B>,
}

impl<B: SnarkBackend> CommitmentPass<B> {
    pub fn new(
        mv_pcs_param: Arc<<B::MvPCS as PCS<B::F>>::ProverParam>,
        ctx_oracles: CtxOracles<B>,
        allow_table_scan_commit_without_ctx: bool,
    ) -> Self {
        Self {
            mv_pcs_param,
            ctx_oracles,
            allow_table_scan_commit_without_ctx,
            total_committed: AtomicUsize::new(0),
            total_ctx_loaded: AtomicUsize::new(0),
            commitment_cache: Mutex::new(BTreeMap::new()),
        }
    }
}

impl<B: SnarkBackend> Drop for CommitmentPass<B> {
    fn drop(&mut self) {
        info!(
            committed = self.total_committed.load(Ordering::Relaxed),
            "total committed polynomials after commitment pass"
        );
        info!(
            ctx_loaded = self.total_ctx_loaded.load(Ordering::Relaxed),
            "total ctx-oracle polynomials loaded after commitment pass"
        );
    }
}

impl<B> LocalPass<B, ArithPayload<B::F>, CommittedPayload<B>> for CommitmentPass<B>
where
    B: SnarkBackend,
{
    fn order(&self) -> crate::irs::ir::PassOrder {
        crate::irs::ir::PassOrder::PostOrder
    }

    fn transform(
        &self,
        node: &Node<B>,
        _id: NodeId,
        payload: Option<&ArithPayload<B::F>>,
    ) -> Option<CommittedPayload<B>> {
        match payload? {
            ArithPayload::PlanPayload(arith_table) => {
                if node.name() == "TableScan"
                    && let Some(schema) = arith_table.schema()
                {
                    if let Some(oracle) = self.ctx_oracles.table_oracle_for_schema(&schema) {
                        // A cached table-scan commitment is only safe to reuse when it lives
                        // on the same multilinear domain as the current arithmetized table.
                        if oracle.log_size() == arith_table.log_size() {
                            debug!(
                                node = %node.name(),
                                num = %oracle.commitments().len(),
                                log_size = oracle.log_size(),
                                "commitment loaded"
                            );
                            self.total_ctx_loaded
                                .fetch_add(oracle.commitments().len(), Ordering::Relaxed);
                            // The cached ctx oracle was built before side
                            // segments existed and only carries row-domain
                            // commitments. If the freshly arithmetized table
                            // has side columns (e.g. `__chars`), commit them
                            // here so the proof carries those commitments.
                            let cached =
                                oracle.clone().with_external_commitment_source(true);
                            let merged = merge_cached_oracle_with_side_commitments::<B>(
                                cached,
                                arith_table,
                                &self.mv_pcs_param,
                                &self.commitment_cache,
                                &self.total_committed,
                            );
                            return Some(CommittedPayload::PlanPayload(merged));
                        }
                        panic!(
                            "TableScan oracle log_size mismatch for schema {:?}: oracle={}, arith={}",
                            schema,
                            oracle.log_size(),
                            arith_table.log_size()
                        );
                    }
                    if self.allow_table_scan_commit_without_ctx {
                        let commited_payloadd = arith_to_oracle::<B>(
                            arith_table,
                            &self.mv_pcs_param,
                            &self.commitment_cache,
                        );
                        let main_count = commited_payloadd.commitments().len();
                        let side_count = commited_payloadd.side_commitments().len() * 2;
                        debug!(
                            node = %node.name(),
                            num = main_count,
                            side = side_count,
                            "committed"
                        );
                        self.total_committed
                            .fetch_add(main_count + side_count, Ordering::Relaxed);
                        return Some(CommittedPayload::PlanPayload(commited_payloadd));
                    }
                    panic!("Missing ctx_oracle for TableScan schema {:?}", schema);
                }
                let commited_payloadd =
                    arith_to_oracle::<B>(arith_table, &self.mv_pcs_param, &self.commitment_cache);
                let main_count = commited_payloadd.commitments().len();
                // Each side col contributes 2 commitments (data + activator).
                let side_count = commited_payloadd.side_commitments().len() * 2;
                debug!(
                    node = %node.name(),
                    num = main_count,
                    side = side_count,
                    "committed"
                );
                self.total_committed
                    .fetch_add(main_count + side_count, Ordering::Relaxed);

                Some(CommittedPayload::PlanPayload(commited_payloadd))
            }
            ArithPayload::GadgetPayload(map) => {
                let mut out = IndexMap::new();
                let mut num_committed = 0;
                for (key, arith_table) in map {
                    let commitment_payload = arith_to_oracle::<B>(
                        arith_table,
                        &self.mv_pcs_param,
                        &self.commitment_cache,
                    );
                    num_committed += commitment_payload.commitments().len()
                        + commitment_payload.side_commitments().len() * 2;
                    out.insert(key.clone(), commitment_payload);
                }
                debug!( node = %node.name(), num=num_committed, "committed");
                self.total_committed
                    .fetch_add(num_committed, Ordering::Relaxed);

                if out.is_empty() {
                    None
                } else {
                    Some(CommittedPayload::GadgetPayload(out))
                }
            }
        }
    }

    fn name(&self) -> &'static str {
        "Prover Commitment"
    }
}

/// Merge fresh side-domain commitments into a cached row-domain oracle.
/// Used by the TableScan fast-path so cached ctx oracles (which predate side
/// segments) still acquire the per-column `__chars` data + activator
/// commitments produced by the current arithmetized table.
fn merge_cached_oracle_with_side_commitments<B: SnarkBackend>(
    cached: ArithTableOracle<B>,
    arith_table: &arithmetic::table::ArithTable<B::F>,
    mv_pcs_param: &Arc<<B::MvPCS as PCS<B::F>>::ProverParam>,
    cache: &CommitmentCache<B>,
    total_committed: &AtomicUsize,
) -> ArithTableOracle<B> {
    if arith_table.side_cols().is_empty() {
        return cached;
    }
    let commit = |mle_arc: Arc<MLE<B::F>>,
                  field_name: &str|
     -> <B::MvPCS as PCS<B::F>>::Commitment {
        let digest = mle_digest(mle_arc.as_ref());
        if let Some(cached) = cache.lock().unwrap().get(&digest) {
            return cached.clone();
        }
        match B::MvPCS::commit(Arc::clone(mv_pcs_param), &mle_arc) {
            Ok(comm) => {
                cache.lock().unwrap().insert(digest, comm.clone());
                comm
            }
            Err(err) => panic!(
                "failed to commit side polynomial '{}' (log_size={}, len={}): {:?}",
                field_name,
                mle_arc.num_vars(),
                mle_arc.evaluations().len(),
                err
            ),
        }
    };
    let mut side_commitments: IndexMap<
        datafusion::arrow::datatypes::FieldRef,
        arithmetic::table_oracle::ArithSideColOracle<B>,
    > = IndexMap::with_capacity(arith_table.side_cols().len());
    for (field_ref, side) in arith_table.side_cols() {
        // Materialize transient MLE views from raw bytes / active_len.
        // Each Arc is dropped immediately after the commit call returns,
        // so the field-element form never persists past the MSM.
        let data_mle = materialize_side_data_mle::<B::F>(&side.data, side.log_size);
        let data_comm = commit(data_mle, field_ref.name());
        let act_mle =
            materialize_side_activator_mle::<B::F>(side.log_size, side.active_len);
        let act_comm = commit(act_mle, field_ref.name());
        side_commitments.insert(
            field_ref.clone(),
            arithmetic::table_oracle::ArithSideColOracle {
                data: data_comm,
                activator: act_comm,
                log_size: side.log_size,
                active_len: side.active_len,
            },
        );
    }
    total_committed.fetch_add(side_commitments.len() * 2, Ordering::Relaxed);

    // ArithTableOracle has no mutable side_commitments setter — rebuild it
    // with the merged commitments.
    ArithTableOracle::new_with_side_commitments(
        cached.schema(),
        cached.commitments().clone(),
        cached.log_size(),
        side_commitments,
    )
}

fn arith_to_oracle<B: SnarkBackend>(
    arith_table: &arithmetic::table::ArithTable<B::F>,
    mv_pcs_param: &Arc<<B::MvPCS as PCS<B::F>>::ProverParam>,
    cache: &CommitmentCache<B>,
) -> ArithTableOracle<B> {
    // Apply structural-redundancy detection (Constant / Rle) at the
    // commitment boundary. Rows here are ingested arithmetized columns
    // that will live in the tracker for the rest of the query and be
    // committed via MSM — collapsing an all-zeros or few-runs shape into
    // its compact form now saves storage across every subsequent poly
    // read AND lets `commit_impl_inner` take its Constant/Rle fast path
    // (no Vec<F> materialization, one scalar mul instead of a full MSM).
    //
    // Cost is one native-scan-with-early-bail per column; benefit is that
    // activator-shaped columns, all-null columns, and prefix / suffix
    // patterns land in their smallest possible form before the tracker
    // Arc-shares them across the whole pass pipeline.
    //
    // We intentionally do NOT run this inside ark-piop's `.compressed()`
    // (which the tracker calls at every registration): small gadget polys
    // registered in tight inner loops get called hundreds of times per
    // query, and even a cheap native scan there measurably regresses
    // small-table benches. Doing it once at the commitment boundary hits
    // the columns that matter and skips the hot short-lived ones.
    let entries: Vec<(usize, _, _)> = arith_table
        .polynomials()
        .iter()
        .enumerate()
        .map(|(idx, (field_ref, mle_arc))| {
            // Only rebuild if the Arc is uniquely owned OR the redundancy
            // scan finds a compressible shape — otherwise keep the same
            // Arc and avoid disturbing sharing with the tracker.
            let compressed = mle_arc.as_ref().clone().detect_redundancy();
            let arc = if matches!(
                compressed.storage(),
                ark_piop::arithmetic::mat_poly::mle::MLEStorage::Constant { .. }
                    | ark_piop::arithmetic::mat_poly::mle::MLEStorage::Rle { .. }
            ) {
                Arc::new(compressed)
            } else {
                Arc::clone(mle_arc)
            };
            (idx, field_ref.clone(), arc)
        })
        .collect();
    let mut commitments = IndexMap::with_capacity(entries.len());

    #[cfg(feature = "parallel")]
    {
        let mut committed: Vec<(usize, _, _)> = entries
            .par_iter()
            .map(|(idx, field_ref, mle_arc)| {
                let digest = mle_digest(mle_arc.as_ref());
                // Fast path: check cache under a short lock.
                if let Some(cached) = cache.lock().unwrap().get(&digest) {
                    tracing::warn!(field = %field_ref.name(), "commitment cache hit — skipping MSM");
                    return (*idx, field_ref.clone(), cached.clone());
                }
                // Slow path: compute MSM, then insert into cache.
                let commitment = B::MvPCS::commit(Arc::clone(mv_pcs_param), mle_arc)
                    .expect("failed to commit arithmetized polynomial");
                cache
                    .lock()
                    .unwrap()
                    .entry(digest)
                    .or_insert_with(|| commitment.clone());
                (*idx, field_ref.clone(), commitment)
            })
            .collect();
        committed.sort_by_key(|(idx, _, _)| *idx);
        for (_idx, field_ref, commitment) in committed {
            commitments.insert(field_ref, commitment);
        }
    }

    #[cfg(not(feature = "parallel"))]
    {
        for (_idx, field_ref, mle_arc) in entries {
            let digest = mle_digest(mle_arc.as_ref());
            let commitment = if let Some(cached) = cache.lock().unwrap().get(&digest) {
                tracing::warn!(field = %field_ref.name(), "commitment cache hit — skipping MSM");
                cached.clone()
            } else {
                let comm = B::MvPCS::commit(Arc::clone(mv_pcs_param), &mle_arc)
                    .expect("failed to commit arithmetized polynomial");
                cache.lock().unwrap().insert(digest, comm.clone());
                comm
            };
            commitments.insert(field_ref, commitment);
        }
    }

    // Commit side-domain (data, activator) pairs. Each is its own MLE on its
    // own multilinear domain, so commits are computed independently.
    let mut side_commitments: IndexMap<
        datafusion::arrow::datatypes::FieldRef,
        arithmetic::table_oracle::ArithSideColOracle<B>,
    > = IndexMap::with_capacity(arith_table.side_cols().len());
    let commit_with_cache = |mle_arc: Arc<MLE<B::F>>,
                             field_name: &str|
     -> <B::MvPCS as PCS<B::F>>::Commitment {
        let digest = mle_digest(mle_arc.as_ref());
        if let Some(cached) = cache.lock().unwrap().get(&digest) {
            return cached.clone();
        }
        match B::MvPCS::commit(Arc::clone(mv_pcs_param), &mle_arc) {
            Ok(comm) => {
                cache.lock().unwrap().insert(digest, comm.clone());
                comm
            }
            Err(err) => panic!(
                "failed to commit side polynomial '{}' (log_size={}, len={}): {:?}",
                field_name,
                mle_arc.num_vars(),
                mle_arc.evaluations().len(),
                err
            ),
        }
    };
    for (field_ref, side) in arith_table.side_cols() {
        let data_mle = materialize_side_data_mle::<B::F>(&side.data, side.log_size);
        let data_comm = commit_with_cache(data_mle, field_ref.name());
        let act_mle =
            materialize_side_activator_mle::<B::F>(side.log_size, side.active_len);
        let act_comm = commit_with_cache(act_mle, field_ref.name());
        side_commitments.insert(
            field_ref.clone(),
            arithmetic::table_oracle::ArithSideColOracle {
                data: data_comm,
                activator: act_comm,
                log_size: side.log_size,
                active_len: side.active_len,
            },
        );
    }

    let schema = enrich_schema_with_constraint_summary(arith_table.schema());
    ArithTableOracle::new_with_side_commitments(
        schema,
        commitments,
        arith_table.log_size(),
        side_commitments,
    )
}

fn enrich_schema_with_constraint_summary(schema: Option<Schema>) -> Option<Schema> {
    let mut schema = schema?;

    // Build a compact, table-local summary from column metadata so commitment
    // payloads can carry key/relationship hints without re-reading sidecar files.
    let mut pk_cols = Vec::new();
    let mut fk_entries = Vec::new();

    for field in schema.fields() {
        let md = field.metadata();
        let is_pk = md
            .get("tt.pk")
            .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
            .unwrap_or(false);
        if is_pk {
            pk_cols.push(field.name().to_string());
        }

        if let Some(ref_table) = md.get("tt.fk.ref_table") {
            let ref_columns = md
                .get("tt.fk.ref_columns")
                .map(|s| parse_ref_columns(s))
                .unwrap_or_default();
            fk_entries.push(json!({
                "column": field.name(),
                "ref_table": ref_table,
                "ref_columns": ref_columns,
            }));
        }
    }

    let summary = json!({
        "primary_key_columns": pk_cols,
        "foreign_keys": fk_entries,
    });

    let mut metadata = schema.metadata().clone();
    metadata.insert(
        arithmetic::table_oracle::CONSTRAINTS_SUMMARY_METADATA_KEY.to_string(),
        summary.to_string(),
    );
    let fields = schema
        .fields()
        .iter()
        .map(|f| f.as_ref().clone())
        .collect::<Vec<_>>();
    schema = Schema::new_with_metadata(fields, metadata);
    Some(schema)
}

fn parse_ref_columns(raw: &str) -> Vec<String> {
    if raw.trim_start().starts_with('[')
        && let Ok(Value::Array(values)) = serde_json::from_str::<Value>(raw)
    {
        return values
            .into_iter()
            .filter_map(|v| v.as_str().map(ToOwned::to_owned))
            .collect();
    }
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

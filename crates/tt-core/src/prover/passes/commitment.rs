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

/// A side-col data MLE in its native storage (`MLEStorage::U8` or `U32`),
/// 32× and 8× smaller than field elements. The PCS commit expands it for the
/// MSM only.
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

use crate::ctx_oracles::CtxOracles;
use crate::irs::ir::LocalPass;
use crate::irs::nodes::{IsNode, Node, NodeId};
use crate::prover::payloads::{ArithPayload, CommittedPayload};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Commitments keyed by the BLAKE3 digest of an MLE's evaluations, so that
/// identical polynomials across nodes share one MSM.
type CommitmentCache<B> = Mutex<
    BTreeMap<[u8; 32], <<B as SnarkBackend>::MvPCS as PCS<<B as SnarkBackend>::F>>::Commitment>,
>;

/// Commits to each arithmetized column and keeps only the commitments, in an
/// `ArithTableOracle`, which lets the pass run in parallel.
pub struct CommitmentPass<B: SnarkBackend> {
    mv_pcs_param: Arc<<B::MvPCS as PCS<B::F>>::ProverParam>,
    ctx_oracles: CtxOracles<B>,
    allow_table_scan_commit_without_ctx: bool,
    total_committed: AtomicUsize,
    /// Polynomials whose commitments came from the ctx oracles.
    total_ctx_loaded: AtomicUsize,
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
                    // A scan that reads no column (`COUNT(*)`) has no field
                    // to name its table.
                    let oracle = self
                        .ctx_oracles
                        .table_oracle_for_schema(&schema)
                        .or_else(|| {
                            node.scanned_table()
                                .and_then(|table| self.ctx_oracles.table_oracle_by_name(&table))
                        });
                    #[cfg(feature = "test-utils")]
                    let oracle =
                        oracle.filter(|_| !crate::test_utils::dishonest_prover::scans_unowned());
                    if let Some(oracle) = oracle {
                        // A cached table-scan commitment is reusable only on the
                        // multilinear domain of the arithmetized table.
                        if oracle.log_size() == arith_table.log_size() {
                            debug!(
                                node = %node.name(),
                                num = %oracle.commitments().len(),
                                log_size = oracle.log_size(),
                                "commitment loaded"
                            );
                            // The side segments (e.g. `__chars`) of the
                            // columns this query reads are the data owner's
                            // too.
                            let side_commitments: IndexMap<_, _> = arith_table
                                .side_cols()
                                .iter()
                                .map(|(field_ref, side)| {
                                    let committed = oracle
                                        .side_commitment(field_ref.name())
                                        .unwrap_or_else(|| {
                                            panic!(
                                                "ctx_oracle has no side commitments for {}; \
                                                 recommit the table",
                                                field_ref.name()
                                            )
                                        });
                                    assert_eq!(
                                        committed.log_size,
                                        side.log_size,
                                        "side segment {} log_size differs from the ctx_oracle's",
                                        field_ref.name()
                                    );
                                    (field_ref.clone(), committed.clone())
                                })
                                .collect();
                            self.total_ctx_loaded.fetch_add(
                                oracle.commitments().len() + side_commitments.len() * 2,
                                Ordering::Relaxed,
                            );
                            let cached = oracle
                                .clone()
                                .with_external_commitment_source(true)
                                .with_side_commitments(side_commitments);
                            return Some(CommittedPayload::PlanPayload(cached));
                        }
                        panic!(
                            "TableScan oracle log_size mismatch for schema {:?}: oracle={}, arith={}",
                            schema,
                            oracle.log_size(),
                            arith_table.log_size()
                        );
                    }
                    #[cfg(feature = "test-utils")]
                    let allow_without_ctx = self.allow_table_scan_commit_without_ctx
                        || crate::test_utils::dishonest_prover::scans_unowned();
                    #[cfg(not(feature = "test-utils"))]
                    let allow_without_ctx = self.allow_table_scan_commit_without_ctx;
                    if allow_without_ctx {
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

fn arith_to_oracle<B: SnarkBackend>(
    arith_table: &arithmetic::table::ArithTable<B::F>,
    mv_pcs_param: &Arc<<B::MvPCS as PCS<B::F>>::ProverParam>,
    cache: &CommitmentCache<B>,
) -> ArithTableOracle<B> {
    // Detect structural redundancy (Constant / Rle) once, here. These
    // columns stay in the tracker for the whole query, and the compact form
    // saves storage and lets the commit take its Constant/Rle fast path (one
    // scalar mul, no MSM). ark-piop's `.compressed()` does not run this
    // scan: the tracker calls it at every registration, which includes the
    // small gadget polys registered in hot loops.
    let entries: Vec<(usize, _, _)> = arith_table
        .polynomials()
        .iter()
        .enumerate()
        .map(|(idx, (field_ref, mle_arc))| {
            // Keep the same Arc, shared with the tracker, unless the scan
            // finds a compressible shape.
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
                if let Some(cached) = cache.lock().unwrap().get(&digest) {
                    tracing::warn!(field = %field_ref.name(), "commitment cache hit — skipping MSM");
                    return (*idx, field_ref.clone(), cached.clone());
                }
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

    // Side-domain (data, activator) pairs, each an MLE on its own domain.
    let mut side_commitments: IndexMap<
        datafusion::arrow::datatypes::FieldRef,
        arithmetic::table_oracle::ArithSideColOracle<B>,
    > = IndexMap::with_capacity(arith_table.side_cols().len());
    let commit_with_cache =
        |mle_arc: Arc<MLE<B::F>>, field_name: &str| -> <B::MvPCS as PCS<B::F>>::Commitment {
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
        let act_mle = Arc::new(MLE::<B::F>::from_prefix_activator(
            side.active_len,
            side.log_size,
        ));
        let act_comm = commit_with_cache(act_mle, field_ref.name());
        side_commitments.insert(
            field_ref.clone(),
            arithmetic::table_oracle::ArithSideColOracle {
                data: data_comm,
                activator: act_comm,
                log_size: side.log_size,
            },
        );
    }

    let schema = enrich_schema_with_fingerprint_rules(enrich_schema_with_constraint_summary(
        arith_table.schema(),
    ));
    ArithTableOracle::new_with_side_commitments(
        schema,
        commitments,
        arith_table.log_size(),
        side_commitments,
    )
}

/// Records the per-column fingerprint rules this table was encoded under, so
/// that prover and verifier read them from the oracle. Nothing is written
/// when no rules are installed: no string column is fingerprinted then.
/// Records the fingerprint rules of this table's columns. The process may
/// hold other tables' rules too, and an oracle that carried them would
/// clash with another table's rule for a column of the same name.
fn enrich_schema_with_fingerprint_rules(schema: Option<Schema>) -> Option<Schema> {
    let schema = schema?;
    let mut rules = arithmetic::fingerprint::configured_rules();
    rules
        .columns
        .retain(|column, _| schema.fields().iter().any(|field| field.name() == column));
    if rules.columns.is_empty() {
        return Some(schema);
    }
    let mut metadata = schema.metadata().clone();
    metadata.insert(
        arithmetic::table_oracle::FINGERPRINT_RULES_METADATA_KEY.to_string(),
        rules.to_toml_string(),
    );
    let fields = schema
        .fields()
        .iter()
        .map(|f| f.as_ref().clone())
        .collect::<Vec<_>>();
    Some(Schema::new_with_metadata(fields, metadata))
}

fn enrich_schema_with_constraint_summary(schema: Option<Schema>) -> Option<Schema> {
    let mut schema = schema?;

    // A summary of the column metadata, so that the committed payload carries
    // the key and foreign-key hints without the sidecar files.
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

use crate::session::session_context;
use arithmetic::table_oracle::{ArithTableOracle, TrackedTableOracle};
use ark_ff::{Field, Zero};
use ark_piop::{
    SnarkBackend,
    types::CommitmentBinding,
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};
use datafusion::{
    arrow::datatypes::{FieldRef, Schema},
    datasource::{MemTable, TableProvider},
};
use datafusion_common::{DFSchema, DataFusionError};
use indexmap::IndexMap;

use crate::irs::nodes::IsNode;
use crate::{
    ctx_oracles::CtxOracles,
    errors::TTResult,
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
        payloads::{HintDFPayload, PayloadStructure},
    },
    prover::passes::tracking::FingerprintOpenings,
    prover::{
        passes::{
            arithmetization::arithmetize_materialized_table,
            materialization::pad_batches_to_num_rows_with_inactive_padding,
        },
        payloads::MaterializedTable,
    },
    verifier::payloads::TrackedPayload,
};
use std::cell::RefCell;
use std::sync::Arc;

const QUALIFIER_METADATA_KEY: &str = "tt.qualifier";
/// Tracks the commitments of each node's table in the verifier, in the order
/// the prover tracked them. Table-scan commitments come from `ctx_oracles`,
/// the others from the proof.
pub struct TrackingPass<B: SnarkBackend> {
    verifier: RefCell<ArgVerifier<B>>,
    ctx_oracles: CtxOracles<B>,
    output_memtable: Option<Arc<MemTable>>,
    /// The string columns with char-level side polys (from
    /// `Tree::required_side_columns`). The prover emits side commitments for
    /// exactly these, so the verifier must expect the same set to keep the
    /// transcript in sync.
    side_columns: std::collections::BTreeSet<String>,
    /// The fingerprint limbs, per column, a pre-filter tests (from
    /// `Tree::required_fingerprint_columns`). Table scans carry exactly
    /// these `__fp{j}` segments, as on the prover side.
    fingerprint_columns: arithmetic::encoding::FingerprintSelection,
    /// The proof's multiproofs for the fingerprint bins it opens.
    fingerprint_openings: OpeningCursor,
}

/// Walks the proof's fingerprint multiproofs in the order the scans open
/// them, remembering the first that fails.
struct OpeningCursor {
    openings: FingerprintOpenings,
    next: std::cell::Cell<usize>,
    failure: RefCell<Option<String>>,
}

impl OpeningCursor {
    fn next(&self) -> Option<&[arithmetic::fingerprint::merkle::Hash]> {
        let at = self.next.get();
        self.next.set(at + 1);
        self.openings.get(at).map(Vec::as_slice)
    }

    fn fail(&self, why: String) {
        self.failure.borrow_mut().get_or_insert(why);
    }

    /// Every opening was checked and held, and none is left over.
    fn check(&self) -> TTResult<()> {
        let failure = self.failure.borrow().clone().or_else(|| {
            (self.next.get() != self.openings.len()).then(|| {
                format!(
                    "proof carries {} fingerprint openings, the query opens {}",
                    self.openings.len(),
                    self.next.get()
                )
            })
        });
        match failure {
            Some(why) => Err(DataFusionError::Internal(why).into()),
            None => Ok(()),
        }
    }
}

impl<B: SnarkBackend> TrackingPass<B> {
    pub fn new(
        verifier: ArgVerifier<B>,
        ctx_oracles: CtxOracles<B>,
        output_memtable: Option<Arc<MemTable>>,
        side_columns: std::collections::BTreeSet<String>,
        fingerprint_columns: arithmetic::encoding::FingerprintSelection,
        fingerprint_openings: FingerprintOpenings,
    ) -> Self {
        Self {
            verifier: RefCell::new(verifier),
            ctx_oracles,
            output_memtable,
            side_columns,
            fingerprint_columns,
            fingerprint_openings: OpeningCursor {
                openings: fingerprint_openings,
                next: std::cell::Cell::new(0),
                failure: RefCell::new(None),
            },
        }
    }

    pub async fn finish(
        &self,
        tracked_ir: &mut crate::verifier::irs::TrackedIr<B>,
    ) -> TTResult<()> {
        self.fingerprint_openings.check()?;
        let Some(output_memtable) = self.output_memtable.clone() else {
            return Ok(());
        };
        let root = tracked_ir.tree().root();
        if root.name() != "ResultCheck" {
            return Ok(());
        }

        let materialized = Self::materialized_table_from_memtable(output_memtable, None).await?;
        // The final output table has no side segments: no PIOP reads them.
        let arith_table = arithmetize_materialized_table::<B::F>(&materialized, None, None);
        let tracked_table = Self::track_output_table_oracle(&arith_table, &self.verifier);
        let gadget_id = root
            .children()
            .into_iter()
            .find(|child| child.name() == "ResultCheck")
            .map(|child| child.id())
            .ok_or_else(|| {
                DataFusionError::Internal("ResultCheck root missing gadget child".to_string())
            })?;
        let mut gadget_payload = match tracked_ir.payload_for_node(&gadget_id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(
            crate::irs::nodes::utils::result_check::OUTPUT_LABEL.to_string(),
            tracked_table,
        );
        tracked_ir.set_payload_for_node(
            gadget_id,
            Some(PayloadStructure::GadgetPayload(gadget_payload)),
        );
        Ok(())
    }
}

impl<B> LocalPass<B, HintDFPayload, TrackedPayload<B>> for TrackingPass<B>
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
        payload: Option<&HintDFPayload>,
    ) -> Option<TrackedPayload<B>> {
        let payload = payload?;
        match payload {
            HintDFPayload::PlanPayload(hint_df) => {
                if node.name() == "TableScan" {
                    let df_schema = hint_df.data_frame().schema();
                    let base_schema: Schema =
                        <DFSchema as AsRef<Schema>>::as_ref(df_schema).clone();
                    let oracle = infer_table_name_from_df_schema(df_schema)
                        .and_then(|name| self.ctx_oracles.table_oracle_by_name(&name))
                        .or_else(|| self.ctx_oracles.table_oracle_for_schema(&base_schema));
                    if let Some(oracle) = oracle {
                        // Table-scan commitments are public input: they come
                        // from the oracle files, never from the proof.
                        return track_hint_df_from_oracle(
                            hint_df,
                            oracle,
                            &self.verifier,
                            &self.side_columns,
                            &self.fingerprint_columns,
                            &self.fingerprint_openings,
                        )
                        .map(TrackedPayload::PlanPayload);
                    }
                    // A table scan without an oracle: the prover emits side
                    // commitments for `side_columns`, so consume them.
                    return track_hint_df(
                        hint_df,
                        &self.verifier,
                        Some(&self.side_columns),
                        Some(&self.fingerprint_columns),
                    )
                    .map(TrackedPayload::PlanPayload);
                }
                if node.name() == "Compaction" {
                    // A Compaction output re-emits side segments for
                    // `side_columns` (see ArithmetizationPass); consume
                    // their commitments in the prover's order.
                    return track_hint_df(hint_df, &self.verifier, Some(&self.side_columns), None)
                        .map(TrackedPayload::PlanPayload);
                }
                // An intermediate operator: the prover emits no side segments
                // (see ArithmetizationPass), so expect none.
                track_hint_df(hint_df, &self.verifier, None, None).map(TrackedPayload::PlanPayload)
            }
            HintDFPayload::GadgetPayload(map) => {
                let mut out = IndexMap::new();
                for (key, hint_df) in map.iter() {
                    if let Some(table) = track_hint_df(hint_df, &self.verifier, None, None) {
                        out.insert(key.clone(), table);
                    }
                }
                if out.is_empty() {
                    None
                } else {
                    Some(TrackedPayload::GadgetPayload(out))
                }
            }
        }
    }

    fn name(&self) -> &'static str {
        "Verifier Tracking"
    }
}

fn track_hint_df_from_oracle<B: SnarkBackend>(
    hint_df: &crate::irs::nodes::hints::HintDF,
    oracle: &ArithTableOracle<B>,
    verifier: &RefCell<ArgVerifier<B>>,
    side_columns: &std::collections::BTreeSet<String>,
    fingerprint_columns: &arithmetic::encoding::FingerprintSelection,
    fingerprint_openings: &OpeningCursor,
) -> Option<TrackedTableOracle<B>> {
    let df_schema_ref = hint_df.data_frame().schema();
    let base_schema: Schema = <DFSchema as AsRef<Schema>>::as_ref(df_schema_ref).clone();
    let qualified_fields = qualify_fields(df_schema_ref);
    let mut tracked_oracles: IndexMap<_, _> = IndexMap::new();
    let mut side_cols: IndexMap<FieldRef, arithmetic::col_oracle::OracleBundle<B>> =
        IndexMap::new();
    let mut log_size = 0usize;

    let mut verifier = verifier.borrow_mut();
    // The prover's order: every row-domain segment, then every side-domain
    // segment. Both come from the ctx oracle: the side segments hold the
    // characters string gadgets read, and only the data owner's commitment
    // ties them to the committed strings.
    let materialized: Vec<FieldRef> = hint_df
        .field_materialization_iter()
        .filter(|&(_field, should_mat)| *should_mat)
        .map(|(field, _should_mat)| {
            qualified_fields
                .get(field)
                .cloned()
                .unwrap_or_else(|| field.clone())
        })
        .collect();

    // Fingerprint bins opened per column: the oracle holds only each
    // column's root, so their commitments come from the proof, opened
    // against it.
    let mut opened: IndexMap<String, Vec<(usize, TrackedOracle<B>)>> = IndexMap::new();
    for qualified_field in &materialized {
        let fingerprint =
            arithmetic::encoding::selected_limbs(fingerprint_columns, qualified_field.name());
        for segment_field in segment_fields::<B>(qualified_field, fingerprint) {
            if let Some((column, bin)) =
                arithmetic::encoding::fingerprint_limb_of(segment_field.name())
                && oracle.fingerprints().contains_key(column)
            {
                let tracked_oracle = verifier
                    .track_next_mv_com()
                    .expect("verifier should track an opened fingerprint bin");
                opened
                    .entry(column.to_string())
                    .or_default()
                    .push((bin, tracked_oracle.clone()));
                tracked_oracles.insert(segment_field, tracked_oracle);
                continue;
            }
            let commitment = oracle
                .commitments()
                .get(&segment_field)
                .cloned()
                .or_else(|| {
                    oracle
                        .commitments()
                        .iter()
                        .find(|(oracle_field, _)| oracle_field.name() == segment_field.name())
                        .map(|(_, commitment)| commitment.clone())
                })
                .unwrap_or_else(|| {
                    panic!(
                        "ctx_oracle missing commitment for field {}",
                        segment_field.name()
                    )
                });
            // As on the prover, a base-table commitment loaded from context
            // is tracked as external.
            let tracked_oracle = verifier
                .track_mat_mv_com_with_binding(commitment, CommitmentBinding::External)
                .expect("verifier should track ctx_oracle commitment");
            if log_size == 0 {
                log_size = tracked_oracle.log_size();
            } else {
                assert_eq!(
                    log_size,
                    tracked_oracle.log_size(),
                    "segments of one table must share a log_size"
                );
            }
            tracked_oracles.insert(segment_field, tracked_oracle);
        }
    }
    for (column, bins) in &opened {
        let commitments: Vec<_> = bins.iter().map(|(bin, t)| (*bin, t.commitment())).collect();
        let leaves: Vec<_> = commitments.iter().map(|(bin, c)| (*bin, c)).collect();
        let holds = fingerprint_openings
            .next()
            .is_some_and(|siblings| oracle.verify_fingerprint_bins(column, &leaves, siblings));
        if !holds {
            fingerprint_openings.fail(format!(
                "fingerprint bins {:?} of column {column} do not open against its committed root",
                bins.iter().map(|(bin, _)| bin).collect::<Vec<_>>()
            ));
        }
    }
    for qualified_field in &materialized {
        if !side_columns.contains(qualified_field.name()) {
            continue;
        }
        for side_field in side_segment_fields::<B>(qualified_field) {
            let committed = oracle
                .side_commitment(side_field.name())
                .unwrap_or_else(|| {
                    panic!(
                        "ctx_oracle has no side commitments for {}",
                        side_field.name()
                    )
                });
            let data = verifier
                .track_mat_mv_com_with_binding(committed.data.clone(), CommitmentBinding::External)
                .expect("verifier should track ctx_oracle side data commitment");
            let activator = verifier
                .track_mat_mv_com_with_binding(
                    committed.activator.clone(),
                    CommitmentBinding::External,
                )
                .expect("verifier should track ctx_oracle side activator commitment");
            side_cols.insert(
                side_field,
                arithmetic::col_oracle::OracleBundle::new(data, Some(activator)),
            );
        }
    }

    if tracked_oracles.is_empty() {
        None
    } else {
        let schema = Some(build_tracked_schema(
            &base_schema,
            tracked_oracles.keys(),
            oracle.schema_ref(),
        ));
        Some(TrackedTableOracle::new_with_side_cols(
            schema,
            tracked_oracles,
            log_size,
            side_cols,
        ))
    }
}

fn track_hint_df<B: SnarkBackend>(
    hint_df: &crate::irs::nodes::hints::HintDF,
    verifier: &RefCell<ArgVerifier<B>>,
    side_columns: Option<&std::collections::BTreeSet<String>>,
    fingerprint_columns: Option<&arithmetic::encoding::FingerprintSelection>,
) -> Option<TrackedTableOracle<B>> {
    let df_schema_ref = hint_df.data_frame().schema();
    let base_schema: Schema = <DFSchema as AsRef<Schema>>::as_ref(df_schema_ref).clone();
    let qualified_fields = qualify_fields(df_schema_ref);
    let mut tracked_oracles: IndexMap<_, _> = IndexMap::new();
    let mut side_cols: IndexMap<FieldRef, arithmetic::col_oracle::OracleBundle<B>> =
        IndexMap::new();
    let mut log_size = 0usize;

    let mut verifier = verifier.borrow_mut();
    // The prover commits every row-domain segment, then every side-domain
    // segment. Consume the commitments in that order: walk the hint fields
    // once for each.
    let materialized: Vec<FieldRef> = hint_df
        .field_materialization_iter()
        .filter(|&(_field, should_mat)| *should_mat)
        .map(|(field, _should_mat)| {
            qualified_fields
                .get(field)
                .cloned()
                .unwrap_or_else(|| field.clone())
        })
        .collect();

    for qualified_field in &materialized {
        let fingerprint = fingerprint_columns
            .map_or(arithmetic::encoding::FingerprintLimbs::None, |selection| {
                arithmetic::encoding::selected_limbs(selection, qualified_field.name())
            });
        for segment_field in segment_fields::<B>(qualified_field, fingerprint) {
            // The prover commits one polynomial per segment (e.g. hash and
            // `__length` for a string); consume one proof commitment each to
            // keep the tracker ids in sync.
            let oracle = verifier
                .track_next_mv_com()
                .expect("verifier should track prover commitment by id");
            if log_size == 0 {
                log_size = oracle.log_size();
            } else {
                assert_eq!(
                    log_size,
                    oracle.log_size(),
                    "segments of one table must share a log_size"
                );
            }
            tracked_oracles.insert(segment_field, oracle);
        }
    }
    if let Some(side_columns) = side_columns {
        for qualified_field in &materialized {
            if !side_columns.contains(qualified_field.name()) {
                continue;
            }
            for side_field in side_segment_fields::<B>(qualified_field) {
                let data = verifier
                    .track_next_mv_com()
                    .expect("verifier should track side data commitment");
                let activator = verifier
                    .track_next_mv_com()
                    .expect("verifier should track side activator commitment");
                assert_eq!(
                    data.log_size(),
                    activator.log_size(),
                    "side data/activator must share log_size"
                );
                side_cols.insert(
                    side_field,
                    arithmetic::col_oracle::OracleBundle::new(data, Some(activator)),
                );
            }
        }
    }
    if tracked_oracles.is_empty() {
        None
    } else {
        let schema = Some(build_tracked_schema(
            &base_schema,
            tracked_oracles.keys(),
            None,
        ));
        Some(TrackedTableOracle::new_with_side_cols(
            schema,
            tracked_oracles,
            log_size,
            side_cols,
        ))
    }
}

/// The segment fields the prover's arithmetization produces for a hint-df
/// field (e.g. `[col, col__length]` for Utf8, then the selected
/// `fingerprint` limbs). The first segment is the field itself; the others
/// are named `<col>{suffix}` and keep its metadata and nullability.
fn segment_fields<B: SnarkBackend>(
    field: &FieldRef,
    fingerprint: arithmetic::encoding::FingerprintLimbs,
) -> Vec<FieldRef> {
    let mut suffixes = arithmetic::encoding::segment_suffixes_for_type::<B::F>(field.data_type());
    if matches!(
        field.data_type(),
        datafusion::arrow::datatypes::DataType::Utf8
            | datafusion::arrow::datatypes::DataType::LargeUtf8
            | datafusion::arrow::datatypes::DataType::Utf8View
    ) {
        suffixes.extend(arithmetic::encoding::fingerprint_segment_suffixes(
            Some(field.name()),
            fingerprint,
        ));
    }
    if suffixes.len() <= 1 {
        return vec![field.clone()];
    }
    suffixes
        .into_iter()
        .map(|suffix| {
            if suffix.is_empty() {
                field.clone()
            } else {
                let mut new_field = datafusion::arrow::datatypes::Field::new(
                    format!("{}{}", field.name(), suffix),
                    field.data_type().clone(),
                    field.is_nullable(),
                );
                if !field.metadata().is_empty() {
                    new_field = new_field.with_metadata(field.metadata().clone());
                }
                Arc::new(new_field)
            }
        })
        .collect()
}

/// The side-domain segment fields the prover's encoder emits for a hint-df
/// field (e.g. `<col>__chars` for Utf8).
fn side_segment_fields<B: SnarkBackend>(field: &FieldRef) -> Vec<FieldRef> {
    let suffixes = arithmetic::encoding::side_segment_suffixes_for_type::<B::F>(field.data_type());
    suffixes
        .into_iter()
        .map(|suffix| {
            let mut new_field = datafusion::arrow::datatypes::Field::new(
                format!("{}{}", field.name(), suffix),
                field.data_type().clone(),
                field.is_nullable(),
            );
            if !field.metadata().is_empty() {
                new_field = new_field.with_metadata(field.metadata().clone());
            }
            Arc::new(new_field)
        })
        .collect()
}

fn build_tracked_schema<'a>(
    base_schema: &Schema,
    tracked_fields: impl Iterator<Item = &'a FieldRef>,
    oracle_schema: Option<&Schema>,
) -> Schema {
    // Fields follow the tracked_oracles keys. Table metadata is merged from
    // the hint-df schema and the oracle schema.
    let mut metadata = base_schema.metadata().clone();
    if let Some(schema) = oracle_schema {
        metadata.extend(schema.metadata().clone());
    }
    let fields = tracked_fields
        .map(|f| f.as_ref().clone())
        .collect::<Vec<_>>();
    Schema::new_with_metadata(fields, metadata)
}

fn qualify_fields(df_schema: &DFSchema) -> IndexMap<FieldRef, FieldRef> {
    let mut out = IndexMap::new();
    for (qualifier, field) in df_schema.iter() {
        let mut updated = field.as_ref().clone();
        if updated.name() == arithmetic::ACTIVATOR_COL_NAME
            || updated.name() == arithmetic::ROW_ID_COL_NAME
        {
            out.insert(field.clone(), Arc::new(updated));
            continue;
        }
        if let Some(qualifier) = qualifier {
            // The prover's qualifier metadata, to keep the schemas aligned.
            let mut metadata = updated.metadata().clone();
            metadata.insert(QUALIFIER_METADATA_KEY.to_string(), qualifier.to_string());
            updated = updated.with_metadata(metadata);
        }
        out.insert(field.clone(), Arc::new(updated));
    }
    out
}

fn infer_table_name_from_df_schema(schema: &DFSchema) -> Option<String> {
    schema.iter().find_map(|(qualifier, field)| {
        if field.name() == arithmetic::ACTIVATOR_COL_NAME
            || field.name() == arithmetic::ROW_ID_COL_NAME
        {
            return None;
        }
        qualifier.as_ref().map(|qualifier| {
            let qualifier = qualifier.to_string();
            qualifier
                .rsplit('.')
                .next()
                .unwrap_or(&qualifier)
                .to_string()
        })
    })
}

impl<B: SnarkBackend> TrackingPass<B> {
    async fn materialized_table_from_memtable(
        mem_table: Arc<MemTable>,
        target_num_rows: Option<usize>,
    ) -> TTResult<MaterializedTable> {
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

    fn track_output_table_oracle(
        arith_table: &arithmetic::table::ArithTable<B::F>,
        verifier: &RefCell<ArgVerifier<B>>,
    ) -> TrackedTableOracle<B> {
        let tracked_oracles = arith_table
            .polynomials()
            .iter()
            .map(|(field_ref, mle)| {
                let poly_evals = mle.evaluations();
                let num_vars = mle.num_vars();
                let oracle = ark_piop::verifier::structs::oracle::Oracle::new_multivariate(
                    arith_table.log_size(),
                    move |point| {
                        // result_check's verifier reads the result at
                        // hypercube points, where the evaluation is an array
                        // lookup: O(num_vars) instead of O(2^num_vars).
                        if let Some(idx) = hypercube_index(&point, num_vars) {
                            return Ok(poly_evals.get(idx).copied().unwrap_or_else(B::F::zero));
                        }
                        Ok(eval_mle_at_point(&poly_evals, num_vars, &point))
                    },
                );
                let tracked_oracle = verifier.borrow().track_base_oracle(oracle);
                (field_ref.clone(), tracked_oracle)
            })
            .collect();
        TrackedTableOracle::new(
            arith_table.schema(),
            tracked_oracles,
            arith_table.log_size(),
        )
    }
}

/// The index `point` encodes (little-endian bits) when every coordinate is
/// 0 or 1, otherwise `None`.
fn hypercube_index<F: Field + Copy>(point: &[F], num_vars: usize) -> Option<usize> {
    let zero = F::zero();
    let one = F::one();
    let mut idx = 0usize;
    for i in 0..num_vars {
        let xi = point.get(i).copied().unwrap_or(zero);
        if xi == zero {
            // bit is 0
        } else if xi == one {
            idx |= 1 << i;
        } else {
            return None;
        }
    }
    Some(idx)
}

fn eval_mle_at_point<F: Field + Copy>(evaluations: &[F], num_vars: usize, point: &[F]) -> F {
    if num_vars == 0 {
        return evaluations.first().copied().unwrap_or_else(F::zero);
    }

    let mut layer = evaluations.to_vec();
    let one = F::one();
    for i in 0..num_vars {
        let x = point.get(i).copied().unwrap_or_else(F::zero);
        let mut next = Vec::with_capacity(layer.len() / 2);
        for &[low, high] in layer.as_chunks::<2>().0 {
            next.push(low * (one - x) + high * x);
        }
        layer = next;
    }
    layer[0]
}

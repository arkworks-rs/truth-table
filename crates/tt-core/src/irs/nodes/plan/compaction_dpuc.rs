//! Wiring for the Domain-Preserving Update Check (TruthTable++ Full String
//! Validity Check, §4.2.2, PIOP 3), B1 variant, on the compaction node's
//! output.
//!
//! Compaction repacks a filtered table's active rows into a smaller
//! hypercube and materializes every column afresh, including the char-domain
//! side segments of a string column (`__chars`, `__orig_ind`, `__int_ind`)
//! that the LIKE gadget reads. The base compaction check (BoolCheck + a
//! row-domain Permutation) binds each new string's hash slots, `__length`
//! and `__fingerprint` to a source row. It does not bind the char domain.
//!
//! This module commits the witnesses the char-domain binding needs and
//! builds the four payload tables of the [`domain_preserving_update_check`]
//! composite. The binding is keyed by the perm-bound hash: each character
//! carries an owning-hash tag `HASHP_k`, the string's hash slot `k`
//! broadcast to the char level, which the composite's broadcast checks tie
//! to the string's hash.
//!
//! It covers a table with exactly one string column that has side segments
//! (see [`single_string_base`]). Any other table has the base compaction
//! gadget alone.

use crate::irs::nodes::utils::u64_field;
use crate::session::session_context;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_FIELD,
    encoding::{
        STRING_CHARS_SUFFIX, STRING_INT_IND_SUFFIX, STRING_LENGTH_SUFFIX, STRING_ORIG_IND_SUFFIX,
    },
    table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::{BigInteger, PrimeField};
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::SnarkResult,
    prover::{ArgProver, structs::polynomial::TrackedPoly, tracker::ProverTracker},
    verifier::{structs::oracle::TrackedOracle, tracker::VerifierTracker},
};
use datafusion::arrow::array::{Array, ArrayRef, BooleanArray, StringArray, UInt64Array};
use datafusion::arrow::compute::cast;
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::prelude::DataFrame;
use datafusion_common::{DataFusionError, Result as DataFusionResult};
use either::Either;
use indexmap::IndexMap;

use crate::irs::nodes::hints::HintDF;
use crate::irs::nodes::utils::domain_preserving_update_check as dpuc;
use crate::irs::nodes::utils::prescr_perm;
use crate::irs::nodes::utils::{commit_with_tracker, track_next_committed};

/// The prover's plan-time copy of the committed `OFFSET_COL`, which the
/// composite's sort-based no-dup child sorts during gadget planning. It
/// reproduces the run-time layout: the string encoder emits chars row-major
/// over the compacted output (`orig-ind` = row index, `int-ind` = byte
/// position; null strings emit nothing) and pads the char domain to
/// `max(1, Σlen).next_power_of_two()`, and [`commit_offset_new`] sets
/// `offset = orig·2^char_domain + int`. Padding is 0 with the activator off.
pub fn build_offset_plan_hint(output_df: DataFrame, base: &str) -> DataFusionResult<HintDF> {
    let batches = crate::session::block_on(output_df.collect())?;
    let mut lens: Vec<usize> = Vec::new();
    for batch in &batches {
        let idx = batch.schema().index_of(base)?;
        let arr = cast(batch.column(idx), &DataType::Utf8)?;
        let arr = arr.as_any().downcast_ref::<StringArray>().ok_or_else(|| {
            DataFusionError::Plan(format!(
                "DPUC offset plan hint: column `{base}` is not a string column"
            ))
        })?;
        lens.extend((0..arr.len()).map(|i| {
            if arr.is_null(i) {
                0
            } else {
                arr.value(i).len()
            }
        }));
    }

    let active: usize = lens.iter().sum();
    let target = active.max(1).next_power_of_two();
    let stride: u64 = 1u64 << target.trailing_zeros();
    let mut offsets: Vec<u64> = Vec::with_capacity(target);
    for (row_ix, &len) in lens.iter().enumerate() {
        offsets.extend((0..len as u64).map(|j| row_ix as u64 * stride + j));
    }
    offsets.resize(target, 0);
    let mut activator = vec![true; active];
    activator.resize(target, false);

    let offset_field = u64_field(dpuc::OFFSET_COL);
    let act_field = ACTIVATOR_FIELD.clone();
    let schema = Arc::new(Schema::new(vec![
        offset_field.as_ref().clone(),
        act_field.as_ref().clone(),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(UInt64Array::from(offsets)) as ArrayRef,
            Arc::new(BooleanArray::from(activator)) as ArrayRef,
        ],
    )?;
    let mem_table = MemTable::try_new(schema, vec![vec![batch]])?;
    let df = session_context().read_table(Arc::new(mem_table))?;

    // Both fields stay virtual: `commit_offset_new` commits the offset at
    // prove time and `set_nodup_prover` hands it to the no-dup. Marked
    // materialized, the tracking pass would commit a duplicate on the prover
    // only (the verifier's hint is schema-only) and shift every later
    // tracker id.
    let mut should_materialize = IndexMap::new();
    should_materialize.insert(offset_field, false);
    should_materialize.insert(act_field, false);
    Ok(HintDF::new(df, should_materialize))
}

/// The base name of the table's string column, iff exactly one column has a
/// `__chars` side segment. `None` disables the DPUC path.
pub fn single_string_base<B: SnarkBackend>(table: &TrackedTable<B>) -> Option<String> {
    let mut found: Option<String> = None;
    for (field, col) in table.tracked_cols_iter() {
        if col.side_segment(STRING_CHARS_SUFFIX).is_some() {
            if found.is_some() {
                return None; // more than one string column
            }
            found = Some(field.name().to_string());
        }
    }
    found
}

/// Verifier mirror of [`single_string_base`].
pub fn single_string_base_verifier<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
) -> Option<String> {
    let mut found: Option<String> = None;
    for (field, col) in table.tracked_col_oracles_iter() {
        if col.side_segment(STRING_CHARS_SUFFIX).is_some() {
            if found.is_some() {
                return None;
            }
            found = Some(field.name().to_string());
        }
    }
    found
}

fn field_to_u64<F: PrimeField>(v: F) -> u64 {
    let bytes = v.into_bigint().to_bytes_le();
    let mut out = 0u64;
    for (i, b) in bytes.iter().take(8).enumerate() {
        out |= (*b as u64) << (8 * i);
    }
    out
}

/// The row-domain hash-slot column names of a string column, in slot order
/// (`base` = slot 0, `base__enc1` = slot 1, …). They are the
/// collision-resistant string id the permutation binds, which is all the
/// char binding needs as a key; length, fingerprint and orig-ind are left
/// out.
fn hash_slot_names(base: &str, schema_fields: &[FieldRef]) -> Vec<String> {
    let mut slots: Vec<(usize, String)> = Vec::new();
    for f in schema_fields {
        let name = f.name();
        if name == base {
            slots.push((0, name.to_string()));
        } else if let Some(rest) = name.strip_prefix(base)
            && let Some(k) = rest.strip_prefix("__enc")
            && let Ok(k) = k.parse::<usize>()
        {
            slots.push((k, name.to_string()));
        }
    }
    slots.sort_by_key(|(k, _)| *k);
    slots.into_iter().map(|(_, n)| n).collect()
}

/// Row-domain poly of `table` by exact field name.
fn row_poly<B: SnarkBackend>(table: &TrackedTable<B>, name: &str) -> TrackedPoly<B> {
    table
        .tracked_polys_iter()
        .find(|(f, _)| f.name() == name)
        .map(|(_, p)| p.clone())
        .unwrap_or_else(|| panic!("compaction DPUC: row column {name} missing"))
}

fn row_oracle<B: SnarkBackend>(table: &TrackedTableOracle<B>, name: &str) -> TrackedOracle<B> {
    table
        .tracked_oracles_iter()
        .find(|(f, _)| f.name() == name)
        .map(|(_, o)| o.clone())
        .unwrap_or_else(|| panic!("compaction DPUC: row column {name} missing"))
}

/// The index poly `[0, 1, …, 2^log_size − 1]`, tracked but not committed.
/// The verifier builds the same identity itself ([`index_oracle_verifier`]),
/// so the prover cannot substitute another one, which would let a
/// character's owning-hash tag point to a different row's hash.
fn index_poly_prover<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    log_size: usize,
) -> TrackedPoly<B> {
    let evals = (0..(1u64 << log_size)).map(B::F::from).collect();
    prover.track_mat_mv_poly(MLE::from_evaluations_vec(log_size, evals))
}

fn index_oracle_verifier<B: SnarkBackend>(
    tracker: &Rc<RefCell<VerifierTracker<B>>>,
    log_size: usize,
) -> TrackedOracle<B> {
    let index_oracle = prescr_perm::shift_permutation_oracle::<B::F>(log_size, 0, true);
    let index_id = tracker.borrow_mut().track_base_oracle(index_oracle);
    TrackedOracle::new(Either::Left(index_id), tracker.clone(), log_size)
}

/// The witnesses of the char-domain binding (prover side).
pub struct DpucWitnesses<B: SnarkBackend> {
    hashp_new: Vec<TrackedPoly<B>>,
    hashp_old: Vec<TrackedPoly<B>>,
    /// NEW-side offset `orig-ind·STRIDE + int-ind`; `STRIDE = 2^char_domain`
    /// makes the encoding injective. It is committed because the no-dup
    /// gadget opens its input, and a zerocheck in the composite binds it to
    /// the formula.
    offset_new: TrackedPoly<B>,
    idx_old: TrackedPoly<B>,
    ind_new: TrackedPoly<B>,
}

/// Verifier mirror.
pub struct DpucWitnessOracles<B: SnarkBackend> {
    hashp_new: Vec<TrackedOracle<B>>,
    hashp_old: Vec<TrackedOracle<B>>,
    offset_new: TrackedOracle<B>,
    idx_old: TrackedOracle<B>,
    ind_new: TrackedOracle<B>,
}

/// Commits the NEW-side offset column `orig-ind·STRIDE + int-ind`, injective
/// since `int-ind < STRIDE = 2^char_domain`. Padding rows are 0, as their
/// orig-ind and int-ind are.
fn commit_offset_new<B: SnarkBackend>(
    output: &TrackedTable<B>,
    base: &str,
    tracker: &Rc<RefCell<ProverTracker<B>>>,
) -> SnarkResult<TrackedPoly<B>> {
    let orig = output
        .side_segment(base, STRING_ORIG_IND_SUFFIX)
        .expect("orig-ind side");
    let int_ind = output
        .side_segment(base, STRING_INT_IND_SUFFIX)
        .expect("int-ind side");
    let char_domain = orig.data.log_size();
    let orig_ev = orig.data.evaluations();
    let int_ev = int_ind.data.evaluations();
    // `char_domain` is a log-size, always < 64.
    let stride = B::F::from(1u64 << char_domain);
    let offset: Vec<B::F> = (0..orig_ev.len())
        .map(|c| orig_ev[c] * stride + int_ev[c])
        .collect();
    commit_with_tracker(tracker, char_domain, offset)
}

/// Broadcast each hash slot to the char level: `hashp[c] =
/// hash_slot[orig-ind[c]]` on active chars (0 elsewhere).
fn broadcast_slots<B: SnarkBackend>(
    table: &TrackedTable<B>,
    base: &str,
    slot_names: &[String],
    tracker: &Rc<RefCell<ProverTracker<B>>>,
) -> SnarkResult<Vec<TrackedPoly<B>>> {
    let orig = table
        .side_segment(base, STRING_ORIG_IND_SUFFIX)
        .expect("orig-ind side");
    let orig_ev = orig.data.evaluations();
    let cact_ev = orig
        .activator
        .as_ref()
        .expect("char-act side activator")
        .evaluations();
    let char_domain = orig.data.log_size();
    let n_chars = orig_ev.len();

    let mut out = Vec::with_capacity(slot_names.len());
    for name in slot_names {
        let hash_ev = row_poly(table, name).evaluations();
        let mut hp = vec![B::F::from(0u64); n_chars];
        for c in 0..n_chars {
            if cact_ev[c] == B::F::from(1u64) {
                let owner = field_to_u64(orig_ev[c]) as usize;
                hp[c] = hash_ev.get(owner).copied().unwrap_or(B::F::from(0u64));
            }
        }
        out.push(commit_with_tracker(tracker, char_domain, hp)?);
    }
    Ok(out)
}

/// Commits the DPUC witnesses in the fixed order the verifier tracks them
/// ([`track_witnesses_verifier`]): every `hashp_new` (slot order), every
/// `hashp_old`, `offset_new`, then `idx_old` and `ind_new`.
pub fn commit_witnesses_prover<B: SnarkBackend>(
    input: &TrackedTable<B>,
    output: &TrackedTable<B>,
    base: &str,
    prover: &mut ArgProver<B>,
) -> SnarkResult<DpucWitnesses<B>> {
    let out_fields: Vec<FieldRef> = output.tracked_polys().keys().cloned().collect();
    let slot_names = hash_slot_names(base, &out_fields);

    let tracker = prover.tracker();
    let hashp_new = broadcast_slots(output, base, &slot_names, &tracker)?;
    let hashp_old = broadcast_slots(input, base, &slot_names, &tracker)?;
    let offset_new = commit_offset_new(output, base, &tracker)?;

    // The index polys are not in the sequence of commitments.
    let idx_old = index_poly_prover(prover, input.log_size());
    let ind_new = index_poly_prover(prover, output.log_size());

    Ok(DpucWitnesses {
        hashp_new,
        hashp_old,
        offset_new,
        idx_old,
        ind_new,
    })
}

/// Tracks the witnesses in the order [`commit_witnesses_prover`] commits
/// them.
pub fn track_witnesses_verifier<B: SnarkBackend>(
    input: &TrackedTableOracle<B>,
    output: &TrackedTableOracle<B>,
    base: &str,
    tracker: &Rc<RefCell<VerifierTracker<B>>>,
) -> SnarkResult<DpucWitnessOracles<B>> {
    let out_fields: Vec<FieldRef> = output.tracked_oracles().keys().cloned().collect();
    let nslots = hash_slot_names(base, &out_fields).len();

    let mut hashp_new = Vec::with_capacity(nslots);
    for _ in 0..nslots {
        hashp_new.push(track_next_committed(tracker)?);
    }
    let mut hashp_old = Vec::with_capacity(nslots);
    for _ in 0..nslots {
        hashp_old.push(track_next_committed(tracker)?);
    }
    let offset_new = track_next_committed(tracker)?;
    let idx_old = index_oracle_verifier(tracker, input.log_size());
    let ind_new = index_oracle_verifier(tracker, output.log_size());

    Ok(DpucWitnessOracles {
        hashp_new,
        hashp_old,
        offset_new,
        idx_old,
        ind_new,
    })
}

/// The four DPUC payload tables (prover), keyed by the composite's labels.
pub fn build_payload_prover<B: SnarkBackend>(
    input: &TrackedTable<B>,
    output: &TrackedTable<B>,
    base: &str,
    w: DpucWitnesses<B>,
) -> IndexMap<String, TrackedTable<B>> {
    let out_fields: Vec<FieldRef> = output.tracked_polys().keys().cloned().collect();
    let slot_names = hash_slot_names(base, &out_fields);
    let length = format!("{base}{STRING_LENGTH_SUFFIX}");

    let str_domain = output.log_size();
    let old_str_domain = input.log_size();
    let a_old = input.activator_tracked_poly().expect("input activator");
    let a_new = output.activator_tracked_poly().expect("output activator");

    // OLD_STR: { idx, hash_slot_k.., length } act a
    let mut old_str = IndexMap::new();
    old_str.insert(u64_field(dpuc::IDX_COL), w.idx_old);
    for (k, name) in slot_names.iter().enumerate() {
        old_str.insert(
            u64_field(&format!("{}{k}", dpuc::HASH_SLOT_PREFIX)),
            row_poly(input, name),
        );
    }
    old_str.insert(u64_field(dpuc::LENGTH_COL), row_poly(input, &length));
    old_str.insert(ACTIVATOR_FIELD.clone(), a_old.clone());
    let old_str_tbl = mk_table(old_str, old_str_domain);

    // NEW_STR: { ind, hash_slot_k.., length } act a
    let mut new_str = IndexMap::new();
    new_str.insert(u64_field(dpuc::IND_COL), w.ind_new);
    for (k, name) in slot_names.iter().enumerate() {
        new_str.insert(
            u64_field(&format!("{}{k}", dpuc::HASH_SLOT_PREFIX)),
            row_poly(output, name),
        );
    }
    new_str.insert(u64_field(dpuc::LENGTH_COL), row_poly(output, &length));
    new_str.insert(ACTIVATOR_FIELD.clone(), a_new.clone());
    let new_str_tbl = mk_table(new_str, str_domain);

    let old_char_tbl = char_table_prover(input, base, w.hashp_old, None);
    let new_char_tbl = char_table_prover(output, base, w.hashp_new, Some(w.offset_new));

    let mut out = IndexMap::new();
    out.insert(dpuc::OLD_STR_LABEL.to_string(), old_str_tbl);
    out.insert(dpuc::NEW_STR_LABEL.to_string(), new_str_tbl);
    out.insert(dpuc::OLD_CHAR_LABEL.to_string(), old_char_tbl);
    out.insert(dpuc::NEW_CHAR_LABEL.to_string(), new_char_tbl);
    out
}

fn mk_table<B: SnarkBackend>(
    polys: IndexMap<FieldRef, TrackedPoly<B>>,
    log_size: usize,
) -> TrackedTable<B> {
    let fields: Vec<Field> = polys
        .keys()
        .filter(|f| f.name() != arithmetic::ACTIVATOR_COL_NAME)
        .map(|f| f.as_ref().clone())
        .collect();
    TrackedTable::new(Some(Schema::new(fields)), polys, log_size)
}

/// Char-domain table `{ orig-ind, int-ind, char, HASHP_k.. }` act char-act.
fn char_table_prover<B: SnarkBackend>(
    table: &TrackedTable<B>,
    base: &str,
    hashp: Vec<TrackedPoly<B>>,
    offset: Option<TrackedPoly<B>>,
) -> TrackedTable<B> {
    let orig = table
        .side_segment(base, STRING_ORIG_IND_SUFFIX)
        .expect("orig-ind side");
    let chars = table
        .side_segment(base, STRING_CHARS_SUFFIX)
        .expect("chars side");
    let int_ind = table
        .side_segment(base, STRING_INT_IND_SUFFIX)
        .expect("int-ind side");
    let char_domain = orig.data.log_size();
    let char_act = orig.activator.clone().expect("char-act side activator");
    let mut polys = IndexMap::new();
    polys.insert(u64_field(dpuc::ORIG_IND_COL), orig.data.clone());
    polys.insert(u64_field(dpuc::INT_IND_COL), int_ind.data.clone());
    polys.insert(u64_field(dpuc::CHAR_COL), chars.data.clone());
    for (k, hp) in hashp.into_iter().enumerate() {
        polys.insert(u64_field(&format!("{}{k}", dpuc::HASHP_SLOT_PREFIX)), hp);
    }
    if let Some(off) = offset {
        polys.insert(u64_field(dpuc::OFFSET_COL), off);
    }
    polys.insert(ACTIVATOR_FIELD.clone(), char_act);
    mk_table(polys, char_domain)
}

/// The four DPUC payload tables (verifier).
pub fn build_payload_verifier<B: SnarkBackend>(
    input: &TrackedTableOracle<B>,
    output: &TrackedTableOracle<B>,
    base: &str,
    w: DpucWitnessOracles<B>,
) -> IndexMap<String, TrackedTableOracle<B>> {
    let out_fields: Vec<FieldRef> = output.tracked_oracles().keys().cloned().collect();
    let slot_names = hash_slot_names(base, &out_fields);
    let length = format!("{base}{STRING_LENGTH_SUFFIX}");

    let str_domain = output.log_size();
    let old_str_domain = input.log_size();
    let a_old = input.activator_tracked_poly().expect("input activator");
    let a_new = output.activator_tracked_poly().expect("output activator");

    let mut old_str = IndexMap::new();
    old_str.insert(u64_field(dpuc::IDX_COL), w.idx_old);
    for (k, name) in slot_names.iter().enumerate() {
        old_str.insert(
            u64_field(&format!("{}{k}", dpuc::HASH_SLOT_PREFIX)),
            row_oracle(input, name),
        );
    }
    old_str.insert(u64_field(dpuc::LENGTH_COL), row_oracle(input, &length));
    old_str.insert(ACTIVATOR_FIELD.clone(), a_old.clone());
    let old_str_tbl = mk_table_oracle(old_str, old_str_domain);

    let mut new_str = IndexMap::new();
    new_str.insert(u64_field(dpuc::IND_COL), w.ind_new);
    for (k, name) in slot_names.iter().enumerate() {
        new_str.insert(
            u64_field(&format!("{}{k}", dpuc::HASH_SLOT_PREFIX)),
            row_oracle(output, name),
        );
    }
    new_str.insert(u64_field(dpuc::LENGTH_COL), row_oracle(output, &length));
    new_str.insert(ACTIVATOR_FIELD.clone(), a_new.clone());
    let new_str_tbl = mk_table_oracle(new_str, str_domain);

    let old_char_tbl = char_table_verifier(input, base, w.hashp_old, None);
    let new_char_tbl = char_table_verifier(output, base, w.hashp_new, Some(w.offset_new));

    let mut out = IndexMap::new();
    out.insert(dpuc::OLD_STR_LABEL.to_string(), old_str_tbl);
    out.insert(dpuc::NEW_STR_LABEL.to_string(), new_str_tbl);
    out.insert(dpuc::OLD_CHAR_LABEL.to_string(), old_char_tbl);
    out.insert(dpuc::NEW_CHAR_LABEL.to_string(), new_char_tbl);
    out
}

fn mk_table_oracle<B: SnarkBackend>(
    oracles: IndexMap<FieldRef, TrackedOracle<B>>,
    log_size: usize,
) -> TrackedTableOracle<B> {
    let fields: Vec<Field> = oracles
        .keys()
        .filter(|f| f.name() != arithmetic::ACTIVATOR_COL_NAME)
        .map(|f| f.as_ref().clone())
        .collect();
    TrackedTableOracle::new(Some(Schema::new(fields)), oracles, log_size)
}

fn char_table_verifier<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    base: &str,
    hashp: Vec<TrackedOracle<B>>,
    offset: Option<TrackedOracle<B>>,
) -> TrackedTableOracle<B> {
    let orig = table
        .side_segment(base, STRING_ORIG_IND_SUFFIX)
        .expect("orig-ind side");
    let chars = table
        .side_segment(base, STRING_CHARS_SUFFIX)
        .expect("chars side");
    let int_ind = table
        .side_segment(base, STRING_INT_IND_SUFFIX)
        .expect("int-ind side");
    let char_domain = orig.data.log_size();
    let char_act = orig.activator.clone().expect("char-act side activator");
    let mut oracles = IndexMap::new();
    oracles.insert(u64_field(dpuc::ORIG_IND_COL), orig.data.clone());
    oracles.insert(u64_field(dpuc::INT_IND_COL), int_ind.data.clone());
    oracles.insert(u64_field(dpuc::CHAR_COL), chars.data.clone());
    for (k, hp) in hashp.into_iter().enumerate() {
        oracles.insert(u64_field(&format!("{}{k}", dpuc::HASHP_SLOT_PREFIX)), hp);
    }
    if let Some(off) = offset {
        oracles.insert(u64_field(dpuc::OFFSET_COL), off);
    }
    oracles.insert(ACTIVATOR_FIELD.clone(), char_act);
    mk_table_oracle(oracles, char_domain)
}

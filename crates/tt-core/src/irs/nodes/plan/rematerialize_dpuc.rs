//! Wiring for the Domain-Preserving Update Check (paper §4.2.2, the
//! "Full String Validity Check"), **B1 variant**, on the rematerialize
//! node's output.
//!
//! Rematerialize repacks a filtered table's active rows into a smaller
//! hypercube, freshly materializing every column — including a string
//! column's char-domain side segments (`__chars`, `__orig_ind`,
//! `__int_ind`) that the LIKE gadget reads. The base remat obligation
//! (BoolCheck + a row-domain **Permutation** that folds every row-domain
//! data column by name) already binds the row domain as a bijection —
//! each new string's hash slots / `__length` / `__fingerprint` match a
//! source row. What it does NOT bind is the char domain, so those side
//! segments crossed the boundary unconstrained.
//!
//! This module commits the extra witnesses the char-domain binding needs
//! and assembles the four payload tables the
//! [`domain_preserving_update_check`] composite consumes. Keyed by the
//! **perm-bound hash** — no `src` provenance: each character carries an
//! owning-hash tag `HASHP_k` = the string's hash slot `k` broadcast down
//! to the char level, committed here and tied to the string's hash by the
//! composite's broadcast checks.
//!
//! Scope: the single-string-column case (the LIKE pre-filter path, where
//! the gap actually bites). Tables with zero or multiple string columns
//! fall back to the base remat gadget — see [`single_string_base`].

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
use datafusion::prelude::{DataFrame, SessionContext};
use datafusion_common::{DataFusionError, Result as DataFusionResult};
use either::Either;
use indexmap::IndexMap;

use crate::irs::nodes::hints::HintDF;
use crate::irs::nodes::utils::domain_preserving_update_check as dpuc;
use crate::irs::nodes::utils::prescr_perm;

/// Plan-time (prover) reconstruction of the committed `OFFSET_COL`, so the
/// composite's sort-based no-dup child can lex-sort it during gadget
/// planning. Reproduces the runtime layout exactly: the string encoder
/// emits chars row-major over the compacted output (`orig-ind` = row
/// index, `int-ind` = byte position; null strings emit nothing), pads the
/// char domain to `max(1, Σlen).next_power_of_two()`, and
/// [`commit_offset_new`] sets `offset = orig·2^char_domain + int`. Padding
/// is `0` with the activator off. The no-dup's permutation argument only
/// needs the multiset and the active count to match, but row order is
/// deterministic anyway (the output is sorted by `__row_id__`).
pub fn build_offset_plan_hint(output_df: DataFrame, base: &str) -> DataFusionResult<HintDF> {
    let batches = crate::irs::nodes::utils::nodup::collect_blocking(output_df, false)?;
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
    let df = SessionContext::new().read_table(Arc::new(mem_table))?;

    // Both fields stay VIRTUAL: the offset is already committed at prove
    // time by `commit_offset_new` and reaches the no-dup through
    // `set_nodup_prover`. Marking it materialized here would make the
    // tracking pass commit a duplicate on the prover only (the verifier's
    // hint is schema-only), shifting every later tracker id.
    let mut should_materialize = IndexMap::new();
    should_materialize.insert(offset_field, false);
    should_materialize.insert(act_field, false);
    Ok(HintDF::new(df, should_materialize))
}

/// Return the base name of the column iff the table has exactly one
/// string column (detected by the `__chars` side segment). `None`
/// disables the DPUC path and keeps the base remat gadget.
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

fn u64_field(name: &str) -> FieldRef {
    Arc::new(Field::new(name, DataType::UInt64, false))
}

fn commit<B: SnarkBackend>(
    tracker: &Rc<RefCell<ProverTracker<B>>>,
    log_size: usize,
    evals: Vec<B::F>,
) -> SnarkResult<TrackedPoly<B>> {
    let mle = MLE::from_evaluations_vec(log_size, evals);
    let nv = mle.num_vars();
    let result = tracker
        .borrow_mut()
        .track_and_commit_mat_mv_p(&mle, false)?;
    Ok(match result {
        Either::Left(id) => TrackedPoly::new(Either::Left(id), nv, tracker.clone()),
        Either::Right((id, c)) => TrackedPoly::new_committed_constant(c, id, nv, tracker.clone()),
    })
}

fn track_next<B: SnarkBackend>(
    tracker: &Rc<RefCell<VerifierTracker<B>>>,
) -> SnarkResult<TrackedOracle<B>> {
    let id = tracker.borrow_mut().peek_next_id();
    let maybe_cnst = tracker.borrow().proof_mv_constant(id);
    if let Some(cnst) = maybe_cnst {
        let (nv, tid) = tracker.borrow_mut().track_mv_com_by_id(id)?;
        return Ok(TrackedOracle::new_committed_constant(
            cnst,
            tid,
            tracker.clone(),
            nv,
        ));
    }
    let (nv, tid) = tracker.borrow_mut().track_mv_com_by_id(id)?;
    Ok(TrackedOracle::new(Either::Left(tid), tracker.clone(), nv))
}

/// The row-domain **hash-slot** column names of a string column, in slot
/// order (`base` = slot 0, `base__enc1` = slot 1, …). These are the
/// collision-resistant string id the perm binds; length / fingerprint /
/// orig-ind are excluded (fingerprint is not needed to key the char
/// binding, and including it would only add broadcasts).
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
        .unwrap_or_else(|| panic!("rematerialize DPUC: row column {name} missing"))
}

fn row_oracle<B: SnarkBackend>(table: &TrackedTableOracle<B>, name: &str) -> TrackedOracle<B> {
    table
        .tracked_oracles_iter()
        .find(|(f, _)| f.name() == name)
        .map(|(_, o)| o.clone())
        .unwrap_or_else(|| panic!("rematerialize DPUC: row column {name} missing"))
}

/// Deterministic canonical index poly `[0, 1, …, 2^log_size − 1]`,
/// tracked but NOT committed (the verifier reconstructs the same identity
/// via [`index_oracle_verifier`], so the prover cannot substitute a
/// non-identity — which would let a character's owning-hash tag point to a
/// different row's hash). Mirrors the join gadget's `index_tracked_poly`.
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

/// Fresh witnesses the char-domain binding needs (prover side).
pub struct DpucWitnesses<B: SnarkBackend> {
    hashp_new: Vec<TrackedPoly<B>>,
    hashp_old: Vec<TrackedPoly<B>>,
    /// NEW-side offset `orig-ind·STRIDE + int-ind` (committed so the
    /// no-dup gadget — which opens its input — has a real column, not a
    /// virtual combo). Bound to the formula by a zerocheck in the
    /// composite. `STRIDE = 2^char_domain` makes the encoding injective.
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

/// Compute the NEW-side offset column `orig-ind·STRIDE + int-ind`
/// (`STRIDE = 2^char_domain`, injective since `int-ind < 2^char_domain`)
/// and commit it. Padding rows are 0 (their orig-ind/int-ind are 0).
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
    // STRIDE = 2^char_domain (char_domain is a log-size, always < 64).
    let stride = B::F::from(1u64 << char_domain);
    let offset: Vec<B::F> = (0..orig_ev.len())
        .map(|c| orig_ev[c] * stride + int_ev[c])
        .collect();
    commit(tracker, char_domain, offset)
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
        out.push(commit(tracker, char_domain, hp)?);
    }
    Ok(out)
}

/// Compute and commit every fresh witness the DPUC needs, in a FIXED
/// order the verifier mirrors ([`track_witnesses_verifier`]):
/// all `hashp_new` (slot order), then all `hashp_old`, then `idx_old`,
/// then `ind_new`.
pub fn commit_witnesses_prover<B: SnarkBackend>(
    input: &TrackedTable<B>,
    output: &TrackedTable<B>,
    base: &str,
    prover: &mut ArgProver<B>,
) -> SnarkResult<DpucWitnesses<B>> {
    let out_fields: Vec<FieldRef> = output.tracked_polys().keys().cloned().collect();
    let slot_names = hash_slot_names(base, &out_fields);

    // Commit the real fresh witnesses (the broadcast hash tags, then the
    // NEW-side offset) FIRST, in the fixed order the verifier tracks them.
    let tracker = prover.tracker();
    let hashp_new = broadcast_slots(output, base, &slot_names, &tracker)?;
    let hashp_old = broadcast_slots(input, base, &slot_names, &tracker)?;
    let offset_new = commit_offset_new(output, base, &tracker)?;

    // Then the identity index polys (deterministic, not in the mv-com seq).
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

/// Verifier mirror: track the fresh witnesses in the same fixed order.
pub fn track_witnesses_verifier<B: SnarkBackend>(
    input: &TrackedTableOracle<B>,
    output: &TrackedTableOracle<B>,
    base: &str,
    tracker: &Rc<RefCell<VerifierTracker<B>>>,
) -> SnarkResult<DpucWitnessOracles<B>> {
    let out_fields: Vec<FieldRef> = output.tracked_oracles().keys().cloned().collect();
    let nslots = hash_slot_names(base, &out_fields).len();

    // Mirror the prover order: track the committed hash tags first, …
    let mut hashp_new = Vec::with_capacity(nslots);
    for _ in 0..nslots {
        hashp_new.push(track_next(tracker)?);
    }
    let mut hashp_old = Vec::with_capacity(nslots);
    for _ in 0..nslots {
        hashp_old.push(track_next(tracker)?);
    }
    let offset_new = track_next(tracker)?;
    // … then the identity index oracles (tracked in the same order).
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

/// Build the four DPUC payload tables (prover), keyed by the composite's
/// labels.
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

/// Build the four DPUC payload tables (verifier).
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

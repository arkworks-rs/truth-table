//! A composite gadget node for paper §6.1 PIOP 8 Factor Placement.
//!
//! Given a fixed factor `p = (str, mode)` of length `ℓ`, current activators
//! `(a, char-act)`, the pre-rotated character columns `{char^(δ)}_{δ=0..ℓ-1}`,
//! fingerprint coefficients `r_0, ..., r_{ℓ-1}`, and the tuple columns
//! `(bnd, orig-ind, int-ind, ind)`, this gadget proves that the prover-sent
//! witnesses `(occurs, match, mark, start)` — plus mode-dependent
//! `(att_mask, {bnd^(δ)}_{δ=1..ℓ-1})` — correctly identify the *leftmost*
//! occurrence of `str` at each string's admissible window, honouring `mode`
//! (prefix / suffix / infix).
//!
//! # Current scope
//!
//! - Only [`Mode::Prefix`] is wired in this cut; suffix and infix are
//!   follow-ups (they add 1 and `ℓ − 1` RotationCheck children respectively
//!   and swap the `att_mask` formula).
//! - **Step 4d (Lookup Check for placement) and Step 4e (leftmost Sign
//!   Check + zerocheck) are stubbed with a TODO**: `start` is committed but
//!   not constrained to be the leftmost of `O_i`, and the string→char
//!   ↔ mark correspondence is only enforced via the two count sumchecks in
//!   step 4c, not via a lookup on the fingerprinted pairs. This is enough
//!   for the honest-prover round-trip; malicious provers could pick a
//!   non-leftmost occurrence. Full soundness requires the two stubbed
//!   steps.
//!
//! # Payload structure
//!
//! - [`CHAR_INPUT_LABEL`] — char-level table `{ char, orig-ind, int-ind, bnd }`
//!   with activator `char-act`.
//! - [`STR_INPUT_LABEL`] — string-level table `{ ind }` with activator `a`.
//! - [`ROTATED_CHAR_LABEL`] — char-level table with `ℓ` data columns
//!   `char^(0), ..., char^(ℓ-1)` in insertion order, no activator.
//!   `char^(0)` should equal the input `char` column; the higher rotations
//!   are verified upstream by Sweep Factors (this gadget trusts them).
//! - [`OCCURS_LABEL`] — char-level table `{ occurs }`, no activator.
//! - [`MATCH_LABEL`] — string-level table `{ match }`, no activator.
//! - [`MARK_LABEL`] — char-level table `{ mark }`, no activator.
//! - [`START_LABEL`] — string-level table `{ start }`, no activator.
//! - [`MATCH_BROADCAST_LABEL`] — char-level table `{ match' }` — the
//!   prover's broadcast of `match` to the char level, no activator.
//!
//! # Decomposition
//!
//! Children (all present under prefix mode):
//! - `BoolCheck` on `occurs`, `match`, `mark` (three children).
//! - `BroadcastCheck` on `(match, match')` — i.e. `match'[c] = match[orig-ind[c]]`.
//! - `NoDup(Bezout)` on `(orig-ind, mark)` — at most one mark per string.
//!
//! Inline claims emitted by `prove`/`verify`:
//! - `att_mask := char-act · bnd` (prefix mode).
//! - Fingerprint challenges `r_0, ..., r_{ℓ-1}` are sampled here (unique
//!   transcript tag per gadget instance).
//! - `wf := Σ r_δ · char^(δ)`, `pf := Σ r_δ · str[δ]`, `diff := wf − pf`.
//! - Zerocheck: `occurs · (1 − att_mask) = 0`.
//! - Zerocheck: `occurs · diff = 0`.
//! - NoZeroCheck: `att_mask · (1 − occurs) · diff + (1 − att_mask · (1 − occurs))`
//!   ≠ 0 everywhere (a Bezout-style "if candidate is unmarked, then diff ≠ 0").
//! - Zerocheck: `occurs · (1 − match') = 0`.
//! - Zerocheck: `mark · (1 − occurs) = 0`.
//! - Sumcheck: `Σ mark = n_m` and `Σ match = n_m`.

use std::marker::PhantomData;
use std::sync::Arc;

use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::Zero;
use ark_piop::{
    SnarkBackend, errors::SnarkResult, prover::structs::polynomial::TrackedPoly,
    verifier::structs::oracle::TrackedOracle,
};
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{
            IsGadgetNode, IsNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
            utils::{bool as bool_check, broadcast_check, nodup},
        },
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub const CHAR_INPUT_LABEL: &str = "__char_input__";
pub const STR_INPUT_LABEL: &str = "__str_input__";
pub const ROTATED_CHAR_LABEL: &str = "__rotated_char__";
pub const OCCURS_LABEL: &str = "__occurs__";
pub const MATCH_LABEL: &str = "__match__";
pub const MARK_LABEL: &str = "__mark__";
pub const START_LABEL: &str = "__start__";
pub const MATCH_BROADCAST_LABEL: &str = "__match_broadcast__";

/// Anchoring mode for the factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Match anchored at each string's start.
    Prefix,
    /// Match anchored at each string's end. (Not yet implemented.)
    Suffix,
    /// Match may occur at any interior position. (Not yet implemented.)
    Infix,
}

fn bool_field() -> FieldRef {
    Arc::new(Field::new("data", DataType::Boolean, false))
}
fn u64_field(name: &str) -> FieldRef {
    Arc::new(Field::new(name, DataType::UInt64, false))
}

/// Composite gadget node for a single factor placement.
pub struct GadgetNode<B: SnarkBackend> {
    pattern: Vec<B::F>,
    mode: Mode,
    bool_occurs: Arc<Node<B>>,
    bool_match: Arc<Node<B>>,
    bool_mark: Arc<Node<B>>,
    broadcast_match: Arc<Node<B>>,
    nodup_mark: Arc<Node<B>>,
    _phantom: PhantomData<B>,
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(pattern: Vec<B::F>, mode: Mode) -> Self {
        assert!(!pattern.is_empty(), "FactorPlacement: pattern must be non-empty");
        assert!(
            matches!(mode, Mode::Prefix),
            "FactorPlacement: only Prefix mode is wired in this cut; suffix/infix are follow-ups"
        );
        let bool_occurs = Arc::new(Node::<B>::Gadget(Arc::new(bool_check::GadgetNode::new())));
        let bool_match = Arc::new(Node::<B>::Gadget(Arc::new(bool_check::GadgetNode::new())));
        let bool_mark = Arc::new(Node::<B>::Gadget(Arc::new(bool_check::GadgetNode::new())));
        let broadcast_match = Arc::new(Node::<B>::Gadget(Arc::new(
            broadcast_check::GadgetNode::new(),
        )));
        let nodup_mark = Arc::new(Node::<B>::Gadget(Arc::new(nodup::GadgetNode::new(
            nodup::Mode::BezoutBased,
        ))));
        Self {
            pattern,
            mode,
            bool_occurs,
            bool_match,
            bool_mark,
            broadcast_match,
            nodup_mark,
            _phantom: PhantomData,
        }
    }

    pub fn pattern_len(&self) -> usize {
        self.pattern.len()
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        format!("FactorPlacement({:?})", self.mode)
    }

    fn display(&self) -> String {
        crate::irs::nodes::display_with_inputs(&self.name(), &self.children())
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        vec![
            self.bool_occurs.clone(),
            self.bool_match.clone(),
            self.bool_mark.clone(),
            self.broadcast_match.clone(),
            self.nodup_mark.clone(),
        ]
    }
}

fn resize_poly<B: SnarkBackend>(p: &TrackedPoly<B>, log_size: usize) -> TrackedPoly<B> {
    TrackedPoly::new(p.id_or_const(), log_size, p.tracker())
}
fn resize_oracle<B: SnarkBackend>(o: &TrackedOracle<B>, log_size: usize) -> TrackedOracle<B> {
    TrackedOracle::new(o.id_or_const(), o.tracker(), log_size)
}

// ---- Payload extraction ----

#[allow(dead_code)]
struct InputsProver<B: SnarkBackend> {
    char_input: TrackedTable<B>,
    str_input: TrackedTable<B>,
    char_col: TrackedPoly<B>,
    orig_ind: TrackedPoly<B>,
    int_ind: TrackedPoly<B>,
    bnd: TrackedPoly<B>,
    char_act: TrackedPoly<B>,
    ind: TrackedPoly<B>,
    a: TrackedPoly<B>,
    rotated_chars: Vec<TrackedPoly<B>>,
    occurs: TrackedPoly<B>,
    match_str: TrackedPoly<B>,
    mark: TrackedPoly<B>,
    // start is committed but currently unused pending Step 4e wiring.
    start: TrackedPoly<B>,
    match_broadcast: TrackedPoly<B>,
}

#[allow(dead_code)]
struct InputsVerifier<B: SnarkBackend> {
    char_input: TrackedTableOracle<B>,
    str_input: TrackedTableOracle<B>,
    char_col: TrackedOracle<B>,
    orig_ind: TrackedOracle<B>,
    int_ind: TrackedOracle<B>,
    bnd: TrackedOracle<B>,
    char_act: TrackedOracle<B>,
    ind: TrackedOracle<B>,
    a: TrackedOracle<B>,
    rotated_chars: Vec<TrackedOracle<B>>,
    occurs: TrackedOracle<B>,
    match_str: TrackedOracle<B>,
    mark: TrackedOracle<B>,
    start: TrackedOracle<B>,
    match_broadcast: TrackedOracle<B>,
}

fn extract_prover_inputs<B: SnarkBackend>(
    ir: &GadgetReadyIr<B>,
    id: NodeId,
) -> InputsProver<B> {
    let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
        panic!("FactorPlacement: missing gadget payload");
    };

    let char_input = payload.get(CHAR_INPUT_LABEL).expect("missing CHAR_INPUT").clone();
    let str_input = payload.get(STR_INPUT_LABEL).expect("missing STR_INPUT").clone();
    let rotated = payload.get(ROTATED_CHAR_LABEL).expect("missing ROTATED_CHAR");
    let occurs_t = payload.get(OCCURS_LABEL).expect("missing OCCURS");
    let match_t = payload.get(MATCH_LABEL).expect("missing MATCH");
    let mark_t = payload.get(MARK_LABEL).expect("missing MARK");
    let start_t = payload.get(START_LABEL).expect("missing START");
    let mbcast_t = payload.get(MATCH_BROADCAST_LABEL).expect("missing MATCH_BROADCAST");

    let char_indices = char_input.data_tracked_polys_indices();
    assert_eq!(
        char_indices.len(),
        4,
        "CHAR_INPUT expects 4 data columns: char, orig-ind, int-ind, bnd"
    );
    let char_col = char_input.tracked_col_by_ind(char_indices[0]).data_tracked_poly();
    let orig_ind = char_input.tracked_col_by_ind(char_indices[1]).data_tracked_poly();
    let int_ind = char_input.tracked_col_by_ind(char_indices[2]).data_tracked_poly();
    let bnd = char_input.tracked_col_by_ind(char_indices[3]).data_tracked_poly();
    let char_act = char_input
        .activator_tracked_poly()
        .expect("CHAR_INPUT must carry activator char-act");

    let str_indices = str_input.data_tracked_polys_indices();
    assert_eq!(str_indices.len(), 1, "STR_INPUT expects 1 data column: ind");
    let ind = str_input.tracked_col_by_ind(str_indices[0]).data_tracked_poly();
    let a = str_input
        .activator_tracked_poly()
        .expect("STR_INPUT must carry activator a");

    let rotated_chars: Vec<TrackedPoly<B>> = rotated
        .data_tracked_polys_indices()
        .into_iter()
        .map(|idx| rotated.tracked_col_by_ind(idx).data_tracked_poly())
        .collect();

    let occurs = single_col(occurs_t, "OCCURS");
    let match_str = single_col(match_t, "MATCH");
    let mark = single_col(mark_t, "MARK");
    let start = single_col(start_t, "START");
    let match_broadcast = single_col(mbcast_t, "MATCH_BROADCAST");

    InputsProver {
        char_input,
        str_input,
        char_col,
        orig_ind,
        int_ind,
        bnd,
        char_act,
        ind,
        a,
        rotated_chars,
        occurs,
        match_str,
        mark,
        start,
        match_broadcast,
    }
}

fn extract_verifier_inputs<B: SnarkBackend>(
    ir: &VerifierGadgetReadyIr<B>,
    id: NodeId,
) -> InputsVerifier<B> {
    let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
        panic!("FactorPlacement: missing gadget payload");
    };

    let char_input = payload.get(CHAR_INPUT_LABEL).expect("missing CHAR_INPUT").clone();
    let str_input = payload.get(STR_INPUT_LABEL).expect("missing STR_INPUT").clone();
    let rotated = payload.get(ROTATED_CHAR_LABEL).expect("missing ROTATED_CHAR");
    let occurs_t = payload.get(OCCURS_LABEL).expect("missing OCCURS");
    let match_t = payload.get(MATCH_LABEL).expect("missing MATCH");
    let mark_t = payload.get(MARK_LABEL).expect("missing MARK");
    let start_t = payload.get(START_LABEL).expect("missing START");
    let mbcast_t = payload.get(MATCH_BROADCAST_LABEL).expect("missing MATCH_BROADCAST");

    let char_indices = char_input.data_tracked_oracles_indices();
    assert_eq!(
        char_indices.len(),
        4,
        "CHAR_INPUT expects 4 data columns: char, orig-ind, int-ind, bnd"
    );
    let char_col = char_input
        .tracked_col_oracle_by_ind(char_indices[0])
        .data_tracked_oracle();
    let orig_ind = char_input
        .tracked_col_oracle_by_ind(char_indices[1])
        .data_tracked_oracle();
    let int_ind = char_input
        .tracked_col_oracle_by_ind(char_indices[2])
        .data_tracked_oracle();
    let bnd = char_input
        .tracked_col_oracle_by_ind(char_indices[3])
        .data_tracked_oracle();
    let char_act = char_input
        .activator_tracked_poly()
        .expect("CHAR_INPUT must carry activator char-act");

    let str_indices = str_input.data_tracked_oracles_indices();
    assert_eq!(str_indices.len(), 1, "STR_INPUT expects 1 data column: ind");
    let ind = str_input
        .tracked_col_oracle_by_ind(str_indices[0])
        .data_tracked_oracle();
    let a = str_input
        .activator_tracked_poly()
        .expect("STR_INPUT must carry activator a");

    let rotated_chars: Vec<TrackedOracle<B>> = rotated
        .data_tracked_oracles_indices()
        .into_iter()
        .map(|idx| rotated.tracked_col_oracle_by_ind(idx).data_tracked_oracle())
        .collect();

    let occurs = single_col_oracle(occurs_t, "OCCURS");
    let match_str = single_col_oracle(match_t, "MATCH");
    let mark = single_col_oracle(mark_t, "MARK");
    let start = single_col_oracle(start_t, "START");
    let match_broadcast = single_col_oracle(mbcast_t, "MATCH_BROADCAST");

    InputsVerifier {
        char_input,
        str_input,
        char_col,
        orig_ind,
        int_ind,
        bnd,
        char_act,
        ind,
        a,
        rotated_chars,
        occurs,
        match_str,
        mark,
        start,
        match_broadcast,
    }
}

fn single_col<B: SnarkBackend>(t: &TrackedTable<B>, label: &str) -> TrackedPoly<B> {
    let indices = t.data_tracked_polys_indices();
    assert_eq!(indices.len(), 1, "FactorPlacement: {label} must be single-column");
    t.tracked_col_by_ind(indices[0]).data_tracked_poly()
}
fn single_col_oracle<B: SnarkBackend>(
    t: &TrackedTableOracle<B>,
    label: &str,
) -> TrackedOracle<B> {
    let indices = t.data_tracked_oracles_indices();
    assert_eq!(indices.len(), 1, "FactorPlacement: {label} must be single-column");
    t.tracked_col_oracle_by_ind(indices[0]).data_tracked_oracle()
}

// ---- Child payload wiring ----

fn set_bool_payload_prover<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    data: &TrackedPoly<B>,
    ir: &mut GadgetReadyIr<B>,
) {
    let mut polys = IndexMap::new();
    polys.insert(bool_field(), data.clone());
    let schema = Schema::new(vec![bool_field().as_ref().clone()]);
    let table = TrackedTable::new(Some(schema), polys, data.log_size());
    let mut payload = IndexMap::new();
    payload.insert(bool_check::TABLE_LABEL.to_string(), table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}
fn set_bool_payload_verifier<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    data: &TrackedOracle<B>,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let mut oracles = IndexMap::new();
    oracles.insert(bool_field(), data.clone());
    let schema = Schema::new(vec![bool_field().as_ref().clone()]);
    let table = TrackedTableOracle::new(Some(schema), oracles, data.log_size());
    let mut payload = IndexMap::new();
    payload.insert(bool_check::TABLE_LABEL.to_string(), table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

/// Broadcast check payload:
/// - STR side: `{ ind, match }` with activator `a` (string data + activator)
/// - CHAR side: `{ orig-ind, match' }` with activator `char-act`
fn set_broadcast_match_payload_prover<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    inputs: &InputsProver<B>,
    ir: &mut GadgetReadyIr<B>,
) {
    let str_domain = inputs.str_input.log_size();
    let char_domain = inputs.char_input.log_size();

    let match_field = u64_field("match");
    let mut str_polys = IndexMap::new();
    str_polys.insert(u64_field("ind"), inputs.ind.clone());
    str_polys.insert(match_field.clone(), inputs.match_str.clone());
    str_polys.insert(
        arithmetic::ACTIVATOR_FIELD.clone(),
        inputs.a.clone(),
    );
    let str_schema = Schema::new(vec![
        Field::new("ind", DataType::UInt64, false),
        Field::new("match", DataType::UInt64, false),
    ]);
    let str_table = TrackedTable::new(Some(str_schema), str_polys, str_domain);

    let match_prime_field = u64_field("match_prime");
    let mut char_polys = IndexMap::new();
    char_polys.insert(u64_field("orig_ind"), inputs.orig_ind.clone());
    char_polys.insert(match_prime_field.clone(), inputs.match_broadcast.clone());
    char_polys.insert(
        arithmetic::ACTIVATOR_FIELD.clone(),
        inputs.char_act.clone(),
    );
    let char_schema = Schema::new(vec![
        Field::new("orig_ind", DataType::UInt64, false),
        Field::new("match_prime", DataType::UInt64, false),
    ]);
    let char_table = TrackedTable::new(Some(char_schema), char_polys, char_domain);

    let mut payload = IndexMap::new();
    payload.insert(broadcast_check::STR_LABEL.to_string(), str_table);
    payload.insert(broadcast_check::CHAR_LABEL.to_string(), char_table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}
fn set_broadcast_match_payload_verifier<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    inputs: &InputsVerifier<B>,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let str_domain = inputs.str_input.log_size();
    let char_domain = inputs.char_input.log_size();

    let mut str_oracles = IndexMap::new();
    str_oracles.insert(u64_field("ind"), inputs.ind.clone());
    str_oracles.insert(u64_field("match"), inputs.match_str.clone());
    str_oracles.insert(arithmetic::ACTIVATOR_FIELD.clone(), inputs.a.clone());
    let str_schema = Schema::new(vec![
        Field::new("ind", DataType::UInt64, false),
        Field::new("match", DataType::UInt64, false),
    ]);
    let str_table = TrackedTableOracle::new(Some(str_schema), str_oracles, str_domain);

    let mut char_oracles = IndexMap::new();
    char_oracles.insert(u64_field("orig_ind"), inputs.orig_ind.clone());
    char_oracles.insert(u64_field("match_prime"), inputs.match_broadcast.clone());
    char_oracles.insert(arithmetic::ACTIVATOR_FIELD.clone(), inputs.char_act.clone());
    let char_schema = Schema::new(vec![
        Field::new("orig_ind", DataType::UInt64, false),
        Field::new("match_prime", DataType::UInt64, false),
    ]);
    let char_table = TrackedTableOracle::new(Some(char_schema), char_oracles, char_domain);

    let mut payload = IndexMap::new();
    payload.insert(broadcast_check::STR_LABEL.to_string(), str_table);
    payload.insert(broadcast_check::CHAR_LABEL.to_string(), char_table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

fn set_nodup_mark_payload_prover<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    inputs: &InputsProver<B>,
    ir: &mut GadgetReadyIr<B>,
) {
    let char_domain = inputs.char_input.log_size();
    let src_f = u64_field("orig_ind");
    let mut polys = IndexMap::new();
    polys.insert(src_f.clone(), inputs.orig_ind.clone());
    polys.insert(arithmetic::ACTIVATOR_FIELD.clone(), inputs.mark.clone());
    let table = TrackedTable::new(
        Some(Schema::new(vec![src_f.as_ref().clone()])),
        polys,
        char_domain,
    );
    let mut payload = IndexMap::new();
    payload.insert(nodup::INPUT_LABEL.to_string(), table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}
fn set_nodup_mark_payload_verifier<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    inputs: &InputsVerifier<B>,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let char_domain = inputs.char_input.log_size();
    let src_f = u64_field("orig_ind");
    let mut oracles = IndexMap::new();
    oracles.insert(src_f.clone(), inputs.orig_ind.clone());
    oracles.insert(arithmetic::ACTIVATOR_FIELD.clone(), inputs.mark.clone());
    let table = TrackedTableOracle::new(
        Some(Schema::new(vec![src_f.as_ref().clone()])),
        oracles,
        char_domain,
    );
    let mut payload = IndexMap::new();
    payload.insert(nodup::INPUT_LABEL.to_string(), table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

// ---- Fingerprint & diff derivation ----

/// Build `wf := Σ r_δ · char^(δ)`, `pf := Σ r_δ · str[δ]`, `diff := wf − pf`.
/// Returns `(diff_poly, pf_scalar)`.
fn build_diff_poly<B: SnarkBackend>(
    rotated_chars: &[TrackedPoly<B>],
    pattern: &[B::F],
    coeffs: &[B::F],
    char_domain: usize,
) -> TrackedPoly<B> {
    assert_eq!(rotated_chars.len(), pattern.len());
    assert_eq!(coeffs.len(), pattern.len());
    // wf = Σ r_δ · char^(δ)
    let mut wf = rotated_chars[0].mul_scalar_poly(coeffs[0]);
    for (chi, r) in rotated_chars.iter().zip(coeffs.iter()).skip(1) {
        let term = chi.mul_scalar_poly(*r);
        wf = &wf + &term;
    }
    let pf: B::F = coeffs
        .iter()
        .zip(pattern.iter())
        .map(|(r, s)| *r * *s)
        .fold(B::F::zero(), |acc, v| acc + v);
    let diff = wf.sub_scalar_poly(pf);
    resize_poly(&diff, char_domain)
}

fn build_diff_oracle<B: SnarkBackend>(
    rotated_chars: &[TrackedOracle<B>],
    pattern: &[B::F],
    coeffs: &[B::F],
    char_domain: usize,
) -> TrackedOracle<B> {
    assert_eq!(rotated_chars.len(), pattern.len());
    assert_eq!(coeffs.len(), pattern.len());
    let mut wf = rotated_chars[0].mul_scalar_oracle(coeffs[0]);
    for (chi, r) in rotated_chars.iter().zip(coeffs.iter()).skip(1) {
        let term = chi.mul_scalar_oracle(*r);
        wf = &wf + &term;
    }
    let pf: B::F = coeffs
        .iter()
        .zip(pattern.iter())
        .map(|(r, s)| *r * *s)
        .fold(B::F::zero(), |acc, v| acc + v);
    let diff = wf.sub_scalar_oracle(pf);
    resize_oracle(&diff, char_domain)
}

fn sum_of_field<B: SnarkBackend>(poly: &TrackedPoly<B>) -> B::F {
    poly.evaluations()
        .into_iter()
        .fold(B::F::zero(), |acc, v| acc + v)
}

fn miscellaneous_key(id: NodeId, tag: &str) -> String {
    format!("factor_placement_{id:?}_{tag}")
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let inputs = extract_prover_inputs(virtualized_ir, id);
        set_bool_payload_prover(&self.bool_occurs, &inputs.occurs, virtualized_ir);
        set_bool_payload_prover(&self.bool_match, &inputs.match_str, virtualized_ir);
        set_bool_payload_prover(&self.bool_mark, &inputs.mark, virtualized_ir);
        set_broadcast_match_payload_prover(&self.broadcast_match, &inputs, virtualized_ir);
        set_nodup_mark_payload_prover(&self.nodup_mark, &inputs, virtualized_ir);
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let inputs = extract_verifier_inputs(virtualized_ir, id);
        set_bool_payload_verifier(&self.bool_occurs, &inputs.occurs, virtualized_ir);
        set_bool_payload_verifier(&self.bool_match, &inputs.match_str, virtualized_ir);
        set_bool_payload_verifier(&self.bool_mark, &inputs.mark, virtualized_ir);
        set_broadcast_match_payload_verifier(&self.broadcast_match, &inputs, virtualized_ir);
        set_nodup_mark_payload_verifier(&self.nodup_mark, &inputs, virtualized_ir);
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        let inputs = extract_prover_inputs(gadget_ready_ir, id);
        let char_domain = inputs.char_input.log_size();

        // Fingerprint coefficients — sampled per instance. Each successive
        // call with the same tag yields a fresh challenge because the
        // transcript has advanced with prior claims.
        let mut coeffs = Vec::with_capacity(self.pattern.len());
        for _ in 0..self.pattern.len() {
            coeffs.push(prover.get_and_append_challenge(b"factor_placement_r")?);
        }

        // att_mask := char-act · bnd (prefix mode).
        let att_mask = &inputs.char_act * &inputs.bnd;
        let att_mask = resize_poly(&att_mask, char_domain);

        // diff := Σ r_δ · char^(δ) − pf
        let diff = build_diff_poly::<B>(
            &inputs.rotated_chars,
            &self.pattern,
            &coeffs,
            char_domain,
        );

        // Step 3(b): Zerocheck on occurs · (1 − att_mask).
        {
            let one_minus_am = att_mask
                .mul_scalar_poly(-B::F::from(1u64))
                .add_scalar_poly(B::F::from(1u64));
            let claim = &inputs.occurs * &one_minus_am;
            prover.add_mv_zerocheck_claim(resize_poly(&claim, char_domain).id())?;
        }

        // Step 3(c): Zerocheck on occurs · diff.
        {
            let claim = &inputs.occurs * &diff;
            prover.add_mv_zerocheck_claim(resize_poly(&claim, char_domain).id())?;
        }

        // Step 3(d): "NoZero on (diff, att_mask · (1 − occurs))" — encoded as
        //   nozerocheck on `am_un · diff + (1 − am_un)` where
        //   `am_un := att_mask · (1 − occurs)`.
        // Collapses to `diff` when am_un = 1 (unmarked candidate) and to
        // 1 elsewhere — so requiring it non-zero everywhere is exactly the
        // paper's "unmarked candidate ⇒ diff ≠ 0".
        {
            let one_minus_occ = inputs
                .occurs
                .mul_scalar_poly(-B::F::from(1u64))
                .add_scalar_poly(B::F::from(1u64));
            let am_un = &att_mask * &one_minus_occ;
            let am_un = resize_poly(&am_un, char_domain);
            let one_minus_am_un = am_un
                .mul_scalar_poly(-B::F::from(1u64))
                .add_scalar_poly(B::F::from(1u64));
            let masked = &am_un * &diff;
            let witness = &resize_poly(&masked, char_domain) + &one_minus_am_un;
            prover.add_mv_nozerocheck_claim(resize_poly(&witness, char_domain).id())?;
        }

        // Step 4(b): no false negatives — occurs · (1 − match') = 0.
        {
            let one_minus_mprime = inputs
                .match_broadcast
                .mul_scalar_poly(-B::F::from(1u64))
                .add_scalar_poly(B::F::from(1u64));
            let claim = &inputs.occurs * &one_minus_mprime;
            prover.add_mv_zerocheck_claim(resize_poly(&claim, char_domain).id())?;
        }

        // Step 4(c) part 1: no false positives — mark · (1 − occurs) = 0.
        {
            let one_minus_occ = inputs
                .occurs
                .mul_scalar_poly(-B::F::from(1u64))
                .add_scalar_poly(B::F::from(1u64));
            let claim = &inputs.mark * &one_minus_occ;
            prover.add_mv_zerocheck_claim(resize_poly(&claim, char_domain).id())?;
        }

        // Step 4(c) part 3: Σ mark = n_m, Σ match = n_m.
        let n_m_mark = sum_of_field::<B>(&inputs.mark);
        let n_m_match = sum_of_field::<B>(&inputs.match_str);
        // Honest prover sanity: they should agree.
        // (Note: not an on-chain check; the two sumchecks with a common
        // claimed value force this at the verifier level.)
        let n_m = n_m_match;
        let _ = n_m_mark;

        let n_m_key = miscellaneous_key(id, "n_m");
        prover.add_miscellaneous_field_element(n_m_key, n_m)?;
        prover.add_mv_sumcheck_claim(inputs.mark.id(), n_m)?;
        prover.add_mv_sumcheck_claim(inputs.match_str.id(), n_m)?;

        // TODO: Step 4(d) LookupCheck on (match, ind+γ·start) ⊑ (mark, orig-ind+γ·int-ind)
        // TODO: Step 4(e) leftmost Sign Check + Zerocheck on
        //       occurs · 1[int-ind < start'] · match'.
        let _ = &inputs.start;
        let _ = &inputs.int_ind;

        Ok(())
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: NodeId,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        let inputs = extract_verifier_inputs(gadget_ready_ir, id);
        let char_domain = inputs.char_input.log_size();

        let mut coeffs = Vec::with_capacity(self.pattern.len());
        for _ in 0..self.pattern.len() {
            coeffs.push(verifier.get_and_append_challenge(b"factor_placement_r")?);
        }

        let att_mask = &inputs.char_act * &inputs.bnd;
        let att_mask = resize_oracle(&att_mask, char_domain);

        let diff = build_diff_oracle::<B>(
            &inputs.rotated_chars,
            &self.pattern,
            &coeffs,
            char_domain,
        );

        {
            let one_minus_am = att_mask
                .mul_scalar_oracle(-B::F::from(1u64))
                .add_scalar_oracle(B::F::from(1u64));
            let claim = &inputs.occurs * &one_minus_am;
            verifier.add_mv_zerocheck_claim(resize_oracle(&claim, char_domain).id());
        }
        {
            let claim = &inputs.occurs * &diff;
            verifier.add_mv_zerocheck_claim(resize_oracle(&claim, char_domain).id());
        }
        {
            let one_minus_occ = inputs
                .occurs
                .mul_scalar_oracle(-B::F::from(1u64))
                .add_scalar_oracle(B::F::from(1u64));
            let am_un = &att_mask * &one_minus_occ;
            let am_un = resize_oracle(&am_un, char_domain);
            let one_minus_am_un = am_un
                .mul_scalar_oracle(-B::F::from(1u64))
                .add_scalar_oracle(B::F::from(1u64));
            let masked = &am_un * &diff;
            let witness = &resize_oracle(&masked, char_domain) + &one_minus_am_un;
            verifier.add_mv_nozerocheck_claim(resize_oracle(&witness, char_domain).id());
        }
        {
            let one_minus_mprime = inputs
                .match_broadcast
                .mul_scalar_oracle(-B::F::from(1u64))
                .add_scalar_oracle(B::F::from(1u64));
            let claim = &inputs.occurs * &one_minus_mprime;
            verifier.add_mv_zerocheck_claim(resize_oracle(&claim, char_domain).id());
        }
        {
            let one_minus_occ = inputs
                .occurs
                .mul_scalar_oracle(-B::F::from(1u64))
                .add_scalar_oracle(B::F::from(1u64));
            let claim = &inputs.mark * &one_minus_occ;
            verifier.add_mv_zerocheck_claim(resize_oracle(&claim, char_domain).id());
        }

        let n_m_key = miscellaneous_key(id, "n_m");
        let n_m = verifier.miscellaneous_field_element(&n_m_key)?;
        verifier.add_mv_sumcheck_claim(inputs.mark.id(), n_m);
        verifier.add_mv_sumcheck_claim(inputs.match_str.id(), n_m);

        let _ = &inputs.start;
        let _ = &inputs.int_ind;
        Ok(())
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

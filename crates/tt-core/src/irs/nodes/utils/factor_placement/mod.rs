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
//! - All three modes ([`Mode::Prefix`], [`Mode::Suffix`], [`Mode::Infix`])
//!   are wired.
//! - **Step 4d (Lookup Check for placement) is wired**: with a fresh
//!   Fiat-Shamir challenge `γ`, the parties do a Lookup Check on
//!   `(match, ind + γ · start) ⊑ (mark, orig-ind + γ · int-ind)`.
//!   Combined with the two count sumchecks in step 4c (both sides have
//!   `n_m` active rows), the ⊑ becomes equality, tying each matched
//!   string's `start` to the `int-ind` of its mark.
//! - **Step 4e (leftmost check) is wired**: prover commits `start'` (the
//!   char-level broadcast of `start`) and a boolean char-level `mask`
//!   with `mask[c] = 1 iff int-ind[c] < start'[c]`. Three children
//!   discharge the correctness of these witnesses:
//!   - [`bool_check`] on `mask`,
//!   - [`broadcast_check`] on `(start, start')`,
//!   - [`sign::SignNode`]`(NonNegative)` on
//!     `mask · (start' - int-ind - 1) + (1 - mask) · (int-ind - start')`,
//!     activated by `char-act` — being `≥ 0` everywhere is equivalent to
//!     `mask` matching its honest value.
//!
//!   Together with the inline zerocheck `occurs · mask · match' = 0`,
//!   any candidate occurrence to the left of the mark is rejected —
//!   so `start` is now the *leftmost* occurrence of each matched string.
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
//! - [`ATT_MASK_LABEL`] — **suffix only** — char-level table `{ att_mask }`
//!   containing `ρ_{-ℓ}(char-act · bnd)`. Verified by an extra
//!   `RotationCheck(Direction::Left, shift=ℓ)` child. Ignored for prefix
//!   and infix.
//! - [`ROTATED_BND_LABEL`] — **infix only** — char-level table with
//!   `ℓ − 1` data columns holding `bnd(1), ..., bnd(ℓ-1)` in insertion
//!   order (each successive column is a shift-left-by-1 of the previous;
//!   `bnd(0)` is the input `bnd` column). Verified by `ℓ − 1`
//!   `RotationCheck(Direction::Left, shift=1)` children on
//!   `(bnd(δ-1), bnd(δ))`. For `ℓ = 1` the table may be absent since the
//!   sum is empty.
//! - [`START_BROADCAST_LABEL`] — char-level table `{ start' }` where
//!   `start'[c] = start[orig-ind[c]]`. Step 4e broadcasts the string-level
//!   `start` to the char domain via a [`broadcast_check`] child.
//! - [`LEFTMOST_MASK_LABEL`] — char-level table `{ mask }` where
//!   `mask[c] = 1 iff int-ind[c] < start'[c]`. Discharged by a
//!   [`bool_check`] child and pinned to its honest value by a
//!   [`sign::SignNode`] child (see the Step 4e block above).
//!
//! # Decomposition
//!
//! Children (fixed 9 + mode-dependent):
//! - `BoolCheck` on `occurs`, `match`, `mark` (three children).
//! - `BroadcastCheck` on `(match, match')` — i.e. `match'[c] = match[orig-ind[c]]`.
//! - `NoDup(Bezout)` on `(orig-ind, mark)` — at most one mark per string.
//! - `Lookup` on `(match, ind + γ · start) ⊑ (mark, orig-ind + γ · int-ind)`
//!   — Step 4d placement check.
//! - `BoolCheck` on `mask` — Step 4e mask booleanity.
//! - `BroadcastCheck` on `(start, start')` — Step 4e start broadcast.
//! - `SignNode(NonNegative)` on the Step 4e mask-selected difference,
//!   activated by `char-act`.
//! - (Suffix only) `RotationCheck(Direction::Left, shift=ℓ)` on
//!   `(char-act · bnd, att_mask)` — proves `att_mask = ρ_{-ℓ}(char-act · bnd)`.
//! - (Infix only) `ℓ − 1` `RotationCheck(Direction::Left, shift=1)`
//!   children forming the chain `bnd(δ-1) → bnd(δ)` for `δ = 1..ℓ-1`.
//!
//! Inline claims emitted by `prove`/`verify`:
//! - `att_mask` derivation depends on mode:
//!   - Prefix: `char-act · bnd` (derived).
//!   - Suffix: payload-supplied `att_mask`.
//!   - Infix: `char-act · (1 − Σ_{δ=1..ℓ-1} bnd(δ))` (derived from the
//!     payload-supplied rotated `bnd` columns).
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
//! - Zerocheck: `occurs · mask · match' = 0` — Step 4e leftmost constraint.

use std::marker::PhantomData;
use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, ROW_ID_COL_NAME, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::Zero;
use ark_piop::{
    SnarkBackend, errors::SnarkError, errors::SnarkResult,
    prover::structs::polynomial::TrackedPoly, verifier::structs::oracle::TrackedOracle,
};
use datafusion::arrow::{
    array::{Array, ArrayRef, BooleanArray, Int64Array},
    datatypes::{DataType, Field, FieldRef, Schema},
    record_batch::RecordBatch,
};
use datafusion::datasource::MemTable;
use datafusion::prelude::SessionContext;
use datafusion_common::Result as DataFusionResult;
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{
            IsGadgetNode, IsNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
            hints::HintDF,
            utils::{bool as bool_check, broadcast_check, lookup, nodup, rotation_check, sign},
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
/// Suffix-only: prover-committed `att_mask = ρ_{-ℓ}(char-act · bnd)`.
pub const ATT_MASK_LABEL: &str = "__att_mask__";
/// Infix-only: prover-committed rotated `bnd(1), ..., bnd(ℓ-1)` columns,
/// in insertion order (each is shift-left-by-1 of the previous, with
/// `bnd(0)` being the input `bnd`). May be absent when `ℓ = 1`.
pub const ROTATED_BND_LABEL: &str = "__rotated_bnd__";
/// Char-level broadcast of `start`: `start'[c] = start[orig_ind[c]]`.
/// Wired to Step 4(e) via a [`broadcast_check`] child on `(start, start')`.
pub const START_BROADCAST_LABEL: &str = "__start_broadcast__";
/// Char-level boolean `mask`: `mask[c] = 1 iff int_ind[c] < start'[c]`.
/// Wired to Step 4(e) via a [`bool_check`] child on `mask` and a
/// [`sign::SignNode`] on `mask · (start' - int_ind - 1) + (1 - mask) ·
/// (int_ind - start')`, which is non-negative iff `mask` is honest.
pub const LEFTMOST_MASK_LABEL: &str = "__leftmost_mask__";

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
    /// Step 4d: Lookup on `(match, ind + γ · start) ⊑ (mark, orig-ind + γ · int-ind)`.
    lookup_placement: Arc<Node<B>>,
    /// Suffix only: proves `att_mask = ρ_{-ℓ}(char-act · bnd)`.
    att_mask_rot_check: Option<Arc<Node<B>>>,
    /// Infix only: `ℓ − 1` rotation checks in a chain, each proving
    /// `bnd(δ) = ρ_{-1}(bnd(δ-1))` for `δ = 1..ℓ-1`.
    bnd_rot_checks: Vec<Arc<Node<B>>>,
    /// Step 4(e): BoolCheck on the prover-committed `mask` column.
    bool_leftmost_mask: Arc<Node<B>>,
    /// Step 4(e): BroadcastCheck on `(start, start_broadcast)` — proves
    /// `start_broadcast[c] = start[orig_ind[c]]`.
    broadcast_start: Arc<Node<B>>,
    /// Step 4(e): NonNegative Sign on the mask-selected difference
    /// `mask · (start' - int_ind - 1) + (1 - mask) · (int_ind - start')`,
    /// activated by `char_act`. Being ≥ 0 everywhere pins `mask` to its
    /// honest value.
    sign_leftmost: Arc<Node<B>>,
    _phantom: PhantomData<B>,
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(pattern: Vec<B::F>, mode: Mode) -> Self {
        Self::new_with_nodup_mode(pattern, mode, nodup::Mode::SortBased)
    }

    /// Test-facing constructor that lets callers pick the nodup_mark
    /// gadget's mode explicitly. Production callers should use
    /// [`Self::new`] which defaults to `SortBased` (required for the
    /// LIKE plan-time pipeline). Test harnesses that skip
    /// `initialize_gadget_plans` need `BezoutBased` because its
    /// `initialize_gadgets` is a no-op and doesn't require the
    /// plan-time LEX_SORTED_LABEL hint.
    pub fn new_with_nodup_mode(pattern: Vec<B::F>, mode: Mode, nodup_mode: nodup::Mode) -> Self {
        assert!(
            !pattern.is_empty(),
            "FactorPlacement: pattern must be non-empty"
        );
        let bool_occurs = Arc::new(Node::<B>::Gadget(Arc::new(bool_check::GadgetNode::new())));
        let bool_match = Arc::new(Node::<B>::Gadget(Arc::new(bool_check::GadgetNode::new())));
        let bool_mark = Arc::new(Node::<B>::Gadget(Arc::new(bool_check::GadgetNode::new())));
        let broadcast_match = Arc::new(Node::<B>::Gadget(Arc::new(
            broadcast_check::GadgetNode::new(),
        )));
        let nodup_mark = Arc::new(Node::<B>::Gadget(Arc::new(nodup::GadgetNode::new(
            nodup_mode,
        ))));
        let lookup_placement = Arc::new(Node::<B>::Gadget(Arc::new(lookup::GadgetNode::new())));
        let att_mask_rot_check = match mode {
            Mode::Prefix => None,
            Mode::Suffix => Some(Arc::new(Node::<B>::Gadget(Arc::new(
                rotation_check::GadgetNode::new(pattern.len(), rotation_check::Direction::Left),
            )))),
            Mode::Infix => None,
        };
        let bnd_rot_checks: Vec<Arc<Node<B>>> = match mode {
            Mode::Infix => (1..pattern.len())
                .map(|_| {
                    Arc::new(Node::<B>::Gadget(Arc::new(
                        rotation_check::GadgetNode::new(1, rotation_check::Direction::Left),
                    )))
                })
                .collect(),
            _ => Vec::new(),
        };
        let bool_leftmost_mask =
            Arc::new(Node::<B>::Gadget(Arc::new(bool_check::GadgetNode::new())));
        let broadcast_start = Arc::new(Node::<B>::Gadget(Arc::new(
            broadcast_check::GadgetNode::new(),
        )));
        let sign_leftmost = Arc::new(Node::<B>::Gadget(Arc::new(sign::SignNode::new(
            sign::SignConfig::Uniform(sign::Sign::NonNegative),
        ))));
        Self {
            pattern,
            mode,
            bool_occurs,
            bool_match,
            bool_mark,
            broadcast_match,
            nodup_mark,
            lookup_placement,
            att_mask_rot_check,
            bnd_rot_checks,
            bool_leftmost_mask,
            broadcast_start,
            sign_leftmost,
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
        let mut out = vec![
            self.bool_occurs.clone(),
            self.bool_match.clone(),
            self.bool_mark.clone(),
            self.broadcast_match.clone(),
            self.nodup_mark.clone(),
            self.lookup_placement.clone(),
        ];
        if let Some(ref child) = self.att_mask_rot_check {
            out.push(child.clone());
        }
        out.extend(self.bnd_rot_checks.iter().cloned());
        out.push(self.bool_leftmost_mask.clone());
        out.push(self.broadcast_start.clone());
        out.push(self.sign_leftmost.clone());
        out
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
    /// Suffix only: prover-committed `att_mask = ρ_{-ℓ}(char-act · bnd)`.
    att_mask: Option<TrackedPoly<B>>,
    /// Infix only: prover-committed `bnd(1), ..., bnd(ℓ-1)`. Empty for
    /// non-infix modes or when `ℓ = 1`.
    rotated_bnds: Vec<TrackedPoly<B>>,
    /// Step 4(e): char-level `start'` where `start'[c] = start[orig_ind[c]]`.
    start_broadcast: TrackedPoly<B>,
    /// Step 4(e): char-level `mask` where `mask[c] = 1 iff int_ind[c] < start'[c]`.
    leftmost_mask: TrackedPoly<B>,
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
    /// Suffix only: prover-committed `att_mask`.
    att_mask: Option<TrackedOracle<B>>,
    /// Infix only: prover-committed `bnd(1), ..., bnd(ℓ-1)`.
    rotated_bnds: Vec<TrackedOracle<B>>,
    /// Step 4(e): char-level `start'`.
    start_broadcast: TrackedOracle<B>,
    /// Step 4(e): char-level `mask`.
    leftmost_mask: TrackedOracle<B>,
}

fn extract_prover_inputs<B: SnarkBackend>(
    ir: &GadgetReadyIr<B>,
    id: NodeId,
    mode: Mode,
    pattern_len: usize,
) -> InputsProver<B> {
    let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
        panic!("FactorPlacement: missing gadget payload");
    };

    let char_input = payload
        .get(CHAR_INPUT_LABEL)
        .expect("missing CHAR_INPUT")
        .clone();
    let str_input = payload
        .get(STR_INPUT_LABEL)
        .expect("missing STR_INPUT")
        .clone();
    let rotated = payload
        .get(ROTATED_CHAR_LABEL)
        .expect("missing ROTATED_CHAR");
    let occurs_t = payload.get(OCCURS_LABEL).expect("missing OCCURS");
    let match_t = payload.get(MATCH_LABEL).expect("missing MATCH");
    let mark_t = payload.get(MARK_LABEL).expect("missing MARK");
    let start_t = payload.get(START_LABEL).expect("missing START");
    let mbcast_t = payload
        .get(MATCH_BROADCAST_LABEL)
        .expect("missing MATCH_BROADCAST");
    let start_bcast_t = payload
        .get(START_BROADCAST_LABEL)
        .expect("missing START_BROADCAST");
    let leftmost_mask_t = payload
        .get(LEFTMOST_MASK_LABEL)
        .expect("missing LEFTMOST_MASK");
    let att_mask_t = match mode {
        Mode::Suffix => Some(
            payload
                .get(ATT_MASK_LABEL)
                .expect("missing ATT_MASK (suffix)"),
        ),
        _ => None,
    };
    let rotated_bnds_t = match mode {
        Mode::Infix if pattern_len >= 2 => Some(
            payload
                .get(ROTATED_BND_LABEL)
                .expect("missing ROTATED_BND (infix with ℓ ≥ 2)"),
        ),
        _ => None,
    };

    let char_indices = char_input.data_tracked_polys_indices();
    assert_eq!(
        char_indices.len(),
        4,
        "CHAR_INPUT expects 4 data columns: char, orig-ind, int-ind, bnd"
    );
    let char_col = char_input
        .tracked_col_by_ind(char_indices[0])
        .data_tracked_poly();
    let orig_ind = char_input
        .tracked_col_by_ind(char_indices[1])
        .data_tracked_poly();
    let int_ind = char_input
        .tracked_col_by_ind(char_indices[2])
        .data_tracked_poly();
    let bnd = char_input
        .tracked_col_by_ind(char_indices[3])
        .data_tracked_poly();
    let char_act = char_input
        .activator_tracked_poly()
        .expect("CHAR_INPUT must carry activator char-act");

    let str_indices = str_input.data_tracked_polys_indices();
    assert_eq!(str_indices.len(), 1, "STR_INPUT expects 1 data column: ind");
    let ind = str_input
        .tracked_col_by_ind(str_indices[0])
        .data_tracked_poly();
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
    let start_broadcast = single_col(start_bcast_t, "START_BROADCAST");
    let leftmost_mask = single_col(leftmost_mask_t, "LEFTMOST_MASK");
    let att_mask = att_mask_t.map(|t| single_col(t, "ATT_MASK"));
    let rotated_bnds: Vec<TrackedPoly<B>> = match rotated_bnds_t {
        Some(t) => {
            let indices = t.data_tracked_polys_indices();
            assert_eq!(
                indices.len(),
                pattern_len - 1,
                "ROTATED_BND: expected {} columns (ℓ - 1), got {}",
                pattern_len - 1,
                indices.len()
            );
            indices
                .into_iter()
                .map(|idx| t.tracked_col_by_ind(idx).data_tracked_poly())
                .collect()
        }
        None => Vec::new(),
    };

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
        att_mask,
        rotated_bnds,
        start_broadcast,
        leftmost_mask,
    }
}

fn extract_verifier_inputs<B: SnarkBackend>(
    ir: &VerifierGadgetReadyIr<B>,
    id: NodeId,
    mode: Mode,
    pattern_len: usize,
) -> InputsVerifier<B> {
    let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
        panic!("FactorPlacement: missing gadget payload");
    };

    let char_input = payload
        .get(CHAR_INPUT_LABEL)
        .expect("missing CHAR_INPUT")
        .clone();
    let str_input = payload
        .get(STR_INPUT_LABEL)
        .expect("missing STR_INPUT")
        .clone();
    let rotated = payload
        .get(ROTATED_CHAR_LABEL)
        .expect("missing ROTATED_CHAR");
    let occurs_t = payload.get(OCCURS_LABEL).expect("missing OCCURS");
    let match_t = payload.get(MATCH_LABEL).expect("missing MATCH");
    let mark_t = payload.get(MARK_LABEL).expect("missing MARK");
    let start_t = payload.get(START_LABEL).expect("missing START");
    let mbcast_t = payload
        .get(MATCH_BROADCAST_LABEL)
        .expect("missing MATCH_BROADCAST");
    let start_bcast_t = payload
        .get(START_BROADCAST_LABEL)
        .expect("missing START_BROADCAST");
    let leftmost_mask_t = payload
        .get(LEFTMOST_MASK_LABEL)
        .expect("missing LEFTMOST_MASK");
    let att_mask_t = match mode {
        Mode::Suffix => Some(
            payload
                .get(ATT_MASK_LABEL)
                .expect("missing ATT_MASK (suffix)"),
        ),
        _ => None,
    };
    let rotated_bnds_t = match mode {
        Mode::Infix if pattern_len >= 2 => Some(
            payload
                .get(ROTATED_BND_LABEL)
                .expect("missing ROTATED_BND (infix with ℓ ≥ 2)"),
        ),
        _ => None,
    };

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
    let start_broadcast = single_col_oracle(start_bcast_t, "START_BROADCAST");
    let leftmost_mask = single_col_oracle(leftmost_mask_t, "LEFTMOST_MASK");
    let att_mask = att_mask_t.map(|t| single_col_oracle(t, "ATT_MASK"));
    let rotated_bnds: Vec<TrackedOracle<B>> = match rotated_bnds_t {
        Some(t) => {
            let indices = t.data_tracked_oracles_indices();
            assert_eq!(
                indices.len(),
                pattern_len - 1,
                "ROTATED_BND: expected {} columns (ℓ - 1), got {}",
                pattern_len - 1,
                indices.len()
            );
            indices
                .into_iter()
                .map(|idx| t.tracked_col_oracle_by_ind(idx).data_tracked_oracle())
                .collect()
        }
        None => Vec::new(),
    };

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
        att_mask,
        rotated_bnds,
        start_broadcast,
        leftmost_mask,
    }
}

fn single_col<B: SnarkBackend>(t: &TrackedTable<B>, label: &str) -> TrackedPoly<B> {
    let indices = t.data_tracked_polys_indices();
    assert_eq!(
        indices.len(),
        1,
        "FactorPlacement: {label} must be single-column"
    );
    t.tracked_col_by_ind(indices[0]).data_tracked_poly()
}
fn single_col_oracle<B: SnarkBackend>(t: &TrackedTableOracle<B>, label: &str) -> TrackedOracle<B> {
    let indices = t.data_tracked_oracles_indices();
    assert_eq!(
        indices.len(),
        1,
        "FactorPlacement: {label} must be single-column"
    );
    t.tracked_col_oracle_by_ind(indices[0])
        .data_tracked_oracle()
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
    str_polys.insert(arithmetic::ACTIVATOR_FIELD.clone(), inputs.a.clone());
    let str_schema = Schema::new(vec![
        Field::new("ind", DataType::UInt64, false),
        Field::new("match", DataType::UInt64, false),
    ]);
    let str_table = TrackedTable::new(Some(str_schema), str_polys, str_domain);

    let match_prime_field = u64_field("match_prime");
    let mut char_polys = IndexMap::new();
    char_polys.insert(u64_field("orig_ind"), inputs.orig_ind.clone());
    char_polys.insert(match_prime_field.clone(), inputs.match_broadcast.clone());
    char_polys.insert(arithmetic::ACTIVATOR_FIELD.clone(), inputs.char_act.clone());
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
    // Merge with any pre-existing payload — under SortBased the pipeline
    // has already populated LEX_SORTED_LABEL (from nodup's plan-time hint);
    // starting from a fresh IndexMap would drop it and break SortNoDup.
    let mut payload = match ir.payload_for_node(&node.id()).cloned() {
        Some(PayloadStructure::GadgetPayload(map)) => map,
        _ => IndexMap::new(),
    };
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
    let mut payload = match ir.payload_for_node(&node.id()).cloned() {
        Some(PayloadStructure::GadgetPayload(map)) => map,
        _ => IndexMap::new(),
    };
    payload.insert(nodup::INPUT_LABEL.to_string(), table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

/// Suffix-only: wire the `RotationCheck` child that proves
/// `att_mask = ρ_{-ℓ}(char-act · bnd)`.
fn set_att_mask_rot_check_payload_prover<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    inputs: &InputsProver<B>,
    ir: &mut GadgetReadyIr<B>,
) {
    let char_domain = inputs.char_input.log_size();
    let att_mask = inputs
        .att_mask
        .as_ref()
        .expect("suffix: att_mask must be populated");

    let char_act_bnd = resize_poly(&(&inputs.char_act * &inputs.bnd), char_domain);
    let left_f = u64_field("char_act_bnd");
    let mut left_polys = IndexMap::new();
    left_polys.insert(left_f.clone(), char_act_bnd);
    let left = TrackedTable::new(
        Some(Schema::new(vec![left_f.as_ref().clone()])),
        left_polys,
        char_domain,
    );

    let right_f = u64_field("att_mask");
    let mut right_polys = IndexMap::new();
    right_polys.insert(right_f.clone(), att_mask.clone());
    let right = TrackedTable::new(
        Some(Schema::new(vec![right_f.as_ref().clone()])),
        right_polys,
        char_domain,
    );

    let mut payload = IndexMap::new();
    payload.insert(rotation_check::LEFT_LABEL.to_string(), left);
    payload.insert(rotation_check::RIGHT_LABEL.to_string(), right);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

fn set_att_mask_rot_check_payload_verifier<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    inputs: &InputsVerifier<B>,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let char_domain = inputs.char_input.log_size();
    let att_mask = inputs
        .att_mask
        .as_ref()
        .expect("suffix: att_mask must be populated");

    let char_act_bnd = resize_oracle(&(&inputs.char_act * &inputs.bnd), char_domain);
    let left_f = u64_field("char_act_bnd");
    let mut left_oracles = IndexMap::new();
    left_oracles.insert(left_f.clone(), char_act_bnd);
    let left = TrackedTableOracle::new(
        Some(Schema::new(vec![left_f.as_ref().clone()])),
        left_oracles,
        char_domain,
    );

    let right_f = u64_field("att_mask");
    let mut right_oracles = IndexMap::new();
    right_oracles.insert(right_f.clone(), att_mask.clone());
    let right = TrackedTableOracle::new(
        Some(Schema::new(vec![right_f.as_ref().clone()])),
        right_oracles,
        char_domain,
    );

    let mut payload = IndexMap::new();
    payload.insert(rotation_check::LEFT_LABEL.to_string(), left);
    payload.insert(rotation_check::RIGHT_LABEL.to_string(), right);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

/// Step 4d: wire the Lookup child on
/// `(match, ind + γ · start) ⊑ (mark, orig-ind + γ · int-ind)`. The
/// derived linear combinations are virtual polys built from `γ` sampled
/// via Fiat-Shamir just before this call. `match` and `mark` sit as the
/// respective side's activator.
fn set_lookup_placement_payload_prover<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    inputs: &InputsProver<B>,
    gamma: B::F,
    ir: &mut GadgetReadyIr<B>,
) {
    let str_domain = inputs.str_input.log_size();
    let char_domain = inputs.char_input.log_size();

    let ind_plus_gamma_start = &inputs.ind + &inputs.start.mul_scalar_poly(gamma);
    let ind_plus_gamma_start = resize_poly(&ind_plus_gamma_start, str_domain);
    let orig_plus_gamma_int = &inputs.orig_ind + &inputs.int_ind.mul_scalar_poly(gamma);
    let orig_plus_gamma_int = resize_poly(&orig_plus_gamma_int, char_domain);

    let included_f = u64_field("ind_plus_gamma_start");
    let mut included_polys = IndexMap::new();
    included_polys.insert(included_f.clone(), ind_plus_gamma_start);
    included_polys.insert(
        arithmetic::ACTIVATOR_FIELD.clone(),
        inputs.match_str.clone(),
    );
    let included = TrackedTable::new(
        Some(Schema::new(vec![included_f.as_ref().clone()])),
        included_polys,
        str_domain,
    );

    let super_f = u64_field("orig_plus_gamma_int");
    let mut super_polys = IndexMap::new();
    super_polys.insert(super_f.clone(), orig_plus_gamma_int);
    super_polys.insert(arithmetic::ACTIVATOR_FIELD.clone(), inputs.mark.clone());
    let super_table = TrackedTable::new(
        Some(Schema::new(vec![super_f.as_ref().clone()])),
        super_polys,
        char_domain,
    );

    let mut payload = IndexMap::new();
    payload.insert(lookup::INCLUDED_LABEL.to_string(), included);
    payload.insert(lookup::SUPER_LABEL.to_string(), super_table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

fn set_lookup_placement_payload_verifier<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    inputs: &InputsVerifier<B>,
    gamma: B::F,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let str_domain = inputs.str_input.log_size();
    let char_domain = inputs.char_input.log_size();

    let ind_plus_gamma_start = &inputs.ind + &inputs.start.mul_scalar_oracle(gamma);
    let ind_plus_gamma_start = resize_oracle(&ind_plus_gamma_start, str_domain);
    let orig_plus_gamma_int = &inputs.orig_ind + &inputs.int_ind.mul_scalar_oracle(gamma);
    let orig_plus_gamma_int = resize_oracle(&orig_plus_gamma_int, char_domain);

    let included_f = u64_field("ind_plus_gamma_start");
    let mut included_oracles = IndexMap::new();
    included_oracles.insert(included_f.clone(), ind_plus_gamma_start);
    included_oracles.insert(
        arithmetic::ACTIVATOR_FIELD.clone(),
        inputs.match_str.clone(),
    );
    let included = TrackedTableOracle::new(
        Some(Schema::new(vec![included_f.as_ref().clone()])),
        included_oracles,
        str_domain,
    );

    let super_f = u64_field("orig_plus_gamma_int");
    let mut super_oracles = IndexMap::new();
    super_oracles.insert(super_f.clone(), orig_plus_gamma_int);
    super_oracles.insert(arithmetic::ACTIVATOR_FIELD.clone(), inputs.mark.clone());
    let super_table = TrackedTableOracle::new(
        Some(Schema::new(vec![super_f.as_ref().clone()])),
        super_oracles,
        char_domain,
    );

    let mut payload = IndexMap::new();
    payload.insert(lookup::INCLUDED_LABEL.to_string(), included);
    payload.insert(lookup::SUPER_LABEL.to_string(), super_table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

/// Infix-only: wire each `RotationCheck` in the `bnd(δ-1) → bnd(δ)` chain.
fn set_bnd_chain_rot_check_payloads_prover<B: SnarkBackend>(
    checks: &[Arc<Node<B>>],
    inputs: &InputsProver<B>,
    ir: &mut GadgetReadyIr<B>,
) {
    let char_domain = inputs.char_input.log_size();
    assert_eq!(
        checks.len(),
        inputs.rotated_bnds.len(),
        "infix: rotated_bnds length must match rot_checks length"
    );
    for (delta, check) in checks.iter().enumerate() {
        // check[delta] proves bnd(delta+1) = ρ_{-1}(bnd(delta))
        let left_poly = if delta == 0 {
            inputs.bnd.clone()
        } else {
            inputs.rotated_bnds[delta - 1].clone()
        };
        let right_poly = inputs.rotated_bnds[delta].clone();

        let left_f = u64_field(&format!("bnd_{delta}"));
        let mut left_polys = IndexMap::new();
        left_polys.insert(left_f.clone(), left_poly);
        let left = TrackedTable::new(
            Some(Schema::new(vec![left_f.as_ref().clone()])),
            left_polys,
            char_domain,
        );

        let right_f = u64_field(&format!("bnd_{}", delta + 1));
        let mut right_polys = IndexMap::new();
        right_polys.insert(right_f.clone(), right_poly);
        let right = TrackedTable::new(
            Some(Schema::new(vec![right_f.as_ref().clone()])),
            right_polys,
            char_domain,
        );

        let mut payload = IndexMap::new();
        payload.insert(rotation_check::LEFT_LABEL.to_string(), left);
        payload.insert(rotation_check::RIGHT_LABEL.to_string(), right);
        ir.set_payload_for_node(check.id(), Some(PayloadStructure::GadgetPayload(payload)));
    }
}

fn set_bnd_chain_rot_check_payloads_verifier<B: SnarkBackend>(
    checks: &[Arc<Node<B>>],
    inputs: &InputsVerifier<B>,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let char_domain = inputs.char_input.log_size();
    assert_eq!(
        checks.len(),
        inputs.rotated_bnds.len(),
        "infix: rotated_bnds length must match rot_checks length"
    );
    for (delta, check) in checks.iter().enumerate() {
        let left_oracle = if delta == 0 {
            inputs.bnd.clone()
        } else {
            inputs.rotated_bnds[delta - 1].clone()
        };
        let right_oracle = inputs.rotated_bnds[delta].clone();

        let left_f = u64_field(&format!("bnd_{delta}"));
        let mut left_oracles = IndexMap::new();
        left_oracles.insert(left_f.clone(), left_oracle);
        let left = TrackedTableOracle::new(
            Some(Schema::new(vec![left_f.as_ref().clone()])),
            left_oracles,
            char_domain,
        );

        let right_f = u64_field(&format!("bnd_{}", delta + 1));
        let mut right_oracles = IndexMap::new();
        right_oracles.insert(right_f.clone(), right_oracle);
        let right = TrackedTableOracle::new(
            Some(Schema::new(vec![right_f.as_ref().clone()])),
            right_oracles,
            char_domain,
        );

        let mut payload = IndexMap::new();
        payload.insert(rotation_check::LEFT_LABEL.to_string(), left);
        payload.insert(rotation_check::RIGHT_LABEL.to_string(), right);
        ir.set_payload_for_node(check.id(), Some(PayloadStructure::GadgetPayload(payload)));
    }
}

// ---- Step 4(e) children: leftmost check (broadcast_start + bool_mask + sign) ----

/// Broadcast check payload for `start_broadcast[c] = start[orig_ind[c]]`:
/// - STR side: `{ ind, start }` with activator `a`.
/// - CHAR side: `{ orig_ind, start_broadcast }` with activator `char_act`.
fn set_broadcast_start_payload_prover<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    inputs: &InputsProver<B>,
    ir: &mut GadgetReadyIr<B>,
) {
    let str_domain = inputs.str_input.log_size();
    let char_domain = inputs.char_input.log_size();

    let mut str_polys = IndexMap::new();
    str_polys.insert(u64_field("ind"), inputs.ind.clone());
    str_polys.insert(u64_field("start"), inputs.start.clone());
    str_polys.insert(ACTIVATOR_FIELD.clone(), inputs.a.clone());
    let str_schema = Schema::new(vec![
        Field::new("ind", DataType::UInt64, false),
        Field::new("start", DataType::UInt64, false),
    ]);
    let str_table = TrackedTable::new(Some(str_schema), str_polys, str_domain);

    let mut char_polys = IndexMap::new();
    char_polys.insert(u64_field("orig_ind"), inputs.orig_ind.clone());
    char_polys.insert(u64_field("start_broadcast"), inputs.start_broadcast.clone());
    char_polys.insert(ACTIVATOR_FIELD.clone(), inputs.char_act.clone());
    let char_schema = Schema::new(vec![
        Field::new("orig_ind", DataType::UInt64, false),
        Field::new("start_broadcast", DataType::UInt64, false),
    ]);
    let char_table = TrackedTable::new(Some(char_schema), char_polys, char_domain);

    let mut payload = IndexMap::new();
    payload.insert(broadcast_check::STR_LABEL.to_string(), str_table);
    payload.insert(broadcast_check::CHAR_LABEL.to_string(), char_table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

fn set_broadcast_start_payload_verifier<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    inputs: &InputsVerifier<B>,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let str_domain = inputs.str_input.log_size();
    let char_domain = inputs.char_input.log_size();

    let mut str_oracles = IndexMap::new();
    str_oracles.insert(u64_field("ind"), inputs.ind.clone());
    str_oracles.insert(u64_field("start"), inputs.start.clone());
    str_oracles.insert(ACTIVATOR_FIELD.clone(), inputs.a.clone());
    let str_schema = Schema::new(vec![
        Field::new("ind", DataType::UInt64, false),
        Field::new("start", DataType::UInt64, false),
    ]);
    let str_table = TrackedTableOracle::new(Some(str_schema), str_oracles, str_domain);

    let mut char_oracles = IndexMap::new();
    char_oracles.insert(u64_field("orig_ind"), inputs.orig_ind.clone());
    char_oracles.insert(u64_field("start_broadcast"), inputs.start_broadcast.clone());
    char_oracles.insert(ACTIVATOR_FIELD.clone(), inputs.char_act.clone());
    let char_schema = Schema::new(vec![
        Field::new("orig_ind", DataType::UInt64, false),
        Field::new("start_broadcast", DataType::UInt64, false),
    ]);
    let char_table = TrackedTableOracle::new(Some(char_schema), char_oracles, char_domain);

    let mut payload = IndexMap::new();
    payload.insert(broadcast_check::STR_LABEL.to_string(), str_table);
    payload.insert(broadcast_check::CHAR_LABEL.to_string(), char_table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

/// Sign check payload wrapping the derived `sign_input` — a `Int64`-typed
/// column (differences fit in `i64`) with activator `char_act`. The Sign
/// gadget checks `sign_input * char_act ≥ 0` on the hypercube, which
/// (combined with the BoolCheck on `mask`) pins `mask` to its honest value.
fn sign_input_field() -> FieldRef {
    Arc::new(Field::new(
        "__leftmost_sign_input__",
        DataType::Int64,
        false,
    ))
}

fn set_sign_leftmost_payload_prover<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    sign_input: &TrackedPoly<B>,
    activator: &TrackedPoly<B>,
    log_size: usize,
    ir: &mut GadgetReadyIr<B>,
) {
    let field = sign_input_field();
    let mut polys = IndexMap::new();
    polys.insert(field.clone(), sign_input.clone());
    polys.insert(ACTIVATOR_FIELD.clone(), activator.clone());
    let schema = Schema::new(vec![field.as_ref().clone()]);
    let table = TrackedTable::new(Some(schema), polys, log_size);
    let mut payload = IndexMap::new();
    payload.insert(sign::INPUT_LABEL.to_string(), table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

fn set_sign_leftmost_payload_verifier<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    sign_input: &TrackedOracle<B>,
    activator: &TrackedOracle<B>,
    log_size: usize,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let field = sign_input_field();
    let mut oracles = IndexMap::new();
    oracles.insert(field.clone(), sign_input.clone());
    oracles.insert(ACTIVATOR_FIELD.clone(), activator.clone());
    let schema = Schema::new(vec![field.as_ref().clone()]);
    let table = TrackedTableOracle::new(Some(schema), oracles, log_size);
    let mut payload = IndexMap::new();
    payload.insert(sign::INPUT_LABEL.to_string(), table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

/// Build the derived `sign_input` polynomial for the leftmost Sign check:
///   `mask · (start' - int_ind - 1) + (1 - mask) · (int_ind - start')`
/// Non-negative iff `mask` truthfully indicates `int_ind < start'`.
fn build_leftmost_sign_input_poly<B: SnarkBackend>(inputs: &InputsProver<B>) -> TrackedPoly<B> {
    let mask = &inputs.leftmost_mask;
    let start_bcast = &inputs.start_broadcast;
    let int_ind = &inputs.int_ind;

    // start' - int_ind - 1
    let start_minus_int = start_bcast - int_ind;
    let start_minus_int_minus_one = start_minus_int.sub_scalar_poly(B::F::from(1u64));
    // int_ind - start'
    let int_minus_start = int_ind - start_bcast;

    // mask · (start' - int_ind - 1)
    let term1 = mask * &start_minus_int_minus_one;
    // 1 - mask
    let one_minus_mask = mask
        .mul_scalar_poly(-B::F::from(1u64))
        .add_scalar_poly(B::F::from(1u64));
    // (1 - mask) · (int_ind - start')
    let term2 = &one_minus_mask * &int_minus_start;

    let sign_input = &term1 + &term2;
    resize_poly(&sign_input, inputs.char_input.log_size())
}

fn build_leftmost_sign_input_oracle<B: SnarkBackend>(
    inputs: &InputsVerifier<B>,
) -> TrackedOracle<B> {
    let mask = &inputs.leftmost_mask;
    let start_bcast = &inputs.start_broadcast;
    let int_ind = &inputs.int_ind;

    let start_minus_int = start_bcast - int_ind;
    let start_minus_int_minus_one = start_minus_int.sub_scalar_oracle(B::F::from(1u64));
    let int_minus_start = int_ind - start_bcast;

    let term1 = mask * &start_minus_int_minus_one;
    let one_minus_mask = mask
        .mul_scalar_oracle(-B::F::from(1u64))
        .add_scalar_oracle(B::F::from(1u64));
    let term2 = &one_minus_mask * &int_minus_start;

    let sign_input = &term1 + &term2;
    resize_oracle(&sign_input, inputs.char_input.log_size())
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

/// Deterministic key for `add_miscellaneous_field_element` / lookup by both
/// prover and verifier. We do NOT key by raw NodeId — prover and verifier
/// build separate trees whose pointer-derived ids differ across runs.
/// DFS rank among FactorPlacement nodes stays deterministic across both
/// trees, mirroring the pattern used by `nodup::active_input_rows_misc_key`.
fn miscellaneous_key<B: SnarkBackend>(
    target_id: NodeId,
    tree: &crate::irs::tree::Tree<B>,
    tag: &str,
) -> String {
    fn dfs_rank<B: SnarkBackend>(
        node: &Arc<Node<B>>,
        target_id: NodeId,
        rank: &mut usize,
        found: &mut Option<usize>,
    ) {
        if found.is_some() {
            return;
        }
        let is_fp =
            matches!(node.as_ref(), Node::Gadget(_)) && node.name().starts_with("FactorPlacement");
        if is_fp {
            if node.id() == target_id {
                *found = Some(*rank);
                return;
            }
            *rank += 1;
        }
        for child in node.children() {
            dfs_rank(&child, target_id, rank, found);
            if found.is_some() {
                return;
            }
        }
    }

    let mut rank = 0usize;
    let mut found = None;
    dfs_rank(tree.root(), target_id, &mut rank, &mut found);
    let fp_rank = found.unwrap_or_else(|| {
        panic!(
            "FactorPlacement node id {:?} was not found while computing misc key",
            target_id
        )
    });
    format!("factor_placement_{fp_rank}_{tag}")
}

/// Blocking DataFrame collect that works in both current-thread and
/// multi-thread tokio runtimes.
fn collect_blocking_fp(df: datafusion::prelude::DataFrame) -> DataFusionResult<Vec<RecordBatch>> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => match handle.runtime_flavor() {
            tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(df.collect()))
            }
            tokio::runtime::RuntimeFlavor::CurrentThread => {
                let df_clone = df.clone();
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| {
                            datafusion_common::DataFusionError::Execution(e.to_string())
                        })?;
                    rt.block_on(df_clone.collect())
                })
                .join()
                .map_err(|_| {
                    datafusion_common::DataFusionError::Execution(
                        "factor placement nodup hint collection thread panicked".to_string(),
                    )
                })?
            }
            _ => tokio::task::block_in_place(|| handle.block_on(df.collect())),
        },
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| datafusion_common::DataFusionError::Execution(e.to_string()))?;
            rt.block_on(df.collect())
        }
    }
}

/// Combine LIKE's plan-time `orig_ind` (Int64) and `mark` (Int64
/// {0,1}) virtual HintDFs into the shape SortNoDup expects for
/// `INPUT_LABEL`: an `Int64` data column `orig_ind` plus a `Boolean`
/// activator column, both marked `should_materialize = false`.
fn build_nodup_mark_input_hint(orig_ind: &HintDF, mark: &HintDF) -> DataFusionResult<HintDF> {
    // Pull orig_ind values from the first data column of the orig_ind hint.
    let orig_batches = collect_blocking_fp(orig_ind.data_frame().clone())?;
    let mark_batches = collect_blocking_fp(mark.data_frame().clone())?;

    // Concatenate all batches so we get a single row-aligned view.
    let orig_schema = orig_batches.first().map(|b| b.schema()).ok_or_else(|| {
        datafusion_common::DataFusionError::Plan("empty orig_ind hint".to_string())
    })?;
    let orig_combined = datafusion::arrow::compute::concat_batches(&orig_schema, &orig_batches)?;

    let mark_schema = mark_batches
        .first()
        .map(|b| b.schema())
        .ok_or_else(|| datafusion_common::DataFusionError::Plan("empty mark hint".to_string()))?;
    let mark_combined = datafusion::arrow::compute::concat_batches(&mark_schema, &mark_batches)?;

    let n = orig_combined.num_rows();
    if mark_combined.num_rows() != n {
        return Err(datafusion_common::DataFusionError::Plan(format!(
            "orig_ind/mark row-count mismatch: {} vs {}",
            n,
            mark_combined.num_rows()
        )));
    }

    // Find the "data" columns (first non-system column) of each input.
    let orig_data_idx = orig_combined
        .schema()
        .fields()
        .iter()
        .position(|f| f.name() != ROW_ID_COL_NAME && f.name() != ACTIVATOR_COL_NAME)
        .ok_or_else(|| {
            datafusion_common::DataFusionError::Plan("orig_ind hint has no data column".to_string())
        })?;
    let mark_data_idx = mark_combined
        .schema()
        .fields()
        .iter()
        .position(|f| f.name() != ROW_ID_COL_NAME && f.name() != ACTIVATOR_COL_NAME)
        .ok_or_else(|| {
            datafusion_common::DataFusionError::Plan("mark hint has no data column".to_string())
        })?;

    let orig_arr = orig_combined
        .column(orig_data_idx)
        .as_any()
        .downcast_ref::<Int64Array>()
        .ok_or_else(|| {
            datafusion_common::DataFusionError::Plan(
                "orig_ind hint data column must be Int64".to_string(),
            )
        })?;
    let mark_arr = mark_combined
        .column(mark_data_idx)
        .as_any()
        .downcast_ref::<Int64Array>()
        .ok_or_else(|| {
            datafusion_common::DataFusionError::Plan(
                "mark hint data column must be Int64".to_string(),
            )
        })?;

    let orig_vals: Vec<i64> = (0..n).map(|i| orig_arr.value(i)).collect();
    let mark_vals: Vec<bool> = (0..n).map(|i| mark_arr.value(i) != 0).collect();

    let orig_field = Field::new("orig_ind", DataType::Int64, false);
    let activator_field = ACTIVATOR_FIELD.as_ref().clone();
    let row_id_field = Field::new(ROW_ID_COL_NAME, DataType::Int64, false);
    let schema = Arc::new(Schema::new(vec![
        orig_field.clone(),
        activator_field.clone(),
        row_id_field.clone(),
    ]));

    let orig_out: ArrayRef = Arc::new(Int64Array::from(orig_vals));
    let act_out: ArrayRef = Arc::new(BooleanArray::from(mark_vals));
    let row_out: ArrayRef = Arc::new(Int64Array::from_iter_values(
        (0..n as i64).collect::<Vec<_>>(),
    ));
    let batch = RecordBatch::try_new(schema.clone(), vec![orig_out, act_out, row_out])?;
    let mem_table = MemTable::try_new(schema, vec![vec![batch]])?;
    let ctx = SessionContext::new();
    let df = ctx.read_table(Arc::new(mem_table))?;

    let orig_fref: FieldRef = Arc::new(orig_field);
    let activator_fref: FieldRef = Arc::new(activator_field);
    let row_id_fref: FieldRef = Arc::new(row_id_field);
    let mut should_materialize: IndexMap<FieldRef, bool> = IndexMap::new();
    should_materialize.insert(orig_fref, false);
    should_materialize.insert(activator_fref, false);
    should_materialize.insert(row_id_fref, false);
    Ok(HintDF::new(df, should_materialize))
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
        prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let inputs = extract_prover_inputs(virtualized_ir, id, self.mode, self.pattern.len());
        set_bool_payload_prover(&self.bool_occurs, &inputs.occurs, virtualized_ir);
        set_bool_payload_prover(&self.bool_match, &inputs.match_str, virtualized_ir);
        set_bool_payload_prover(&self.bool_mark, &inputs.mark, virtualized_ir);
        set_broadcast_match_payload_prover(&self.broadcast_match, &inputs, virtualized_ir);
        set_nodup_mark_payload_prover(&self.nodup_mark, &inputs, virtualized_ir);
        // Sample γ for Step 4d BEFORE the Lookup child's own init runs.
        // Both prover and verifier sample it here so their transcripts stay
        // synchronized (initialize_gadgets is a pre-order pass, so this
        // executes before the Lookup child's initialize_gadgets).
        let gamma = prover.get_and_append_challenge(b"factor_placement_gamma")?;
        set_lookup_placement_payload_prover(&self.lookup_placement, &inputs, gamma, virtualized_ir);
        if let Some(ref rot_check) = self.att_mask_rot_check {
            set_att_mask_rot_check_payload_prover(rot_check, &inputs, virtualized_ir);
        }
        if !self.bnd_rot_checks.is_empty() {
            set_bnd_chain_rot_check_payloads_prover(&self.bnd_rot_checks, &inputs, virtualized_ir);
        }
        // Step 4(e): leftmost check — BoolCheck(mask), BroadcastCheck(start),
        // and Sign(NonNegative) on the mask-selected difference.
        set_bool_payload_prover(
            &self.bool_leftmost_mask,
            &inputs.leftmost_mask,
            virtualized_ir,
        );
        set_broadcast_start_payload_prover(&self.broadcast_start, &inputs, virtualized_ir);
        let sign_input = build_leftmost_sign_input_poly(&inputs);
        set_sign_leftmost_payload_prover(
            &self.sign_leftmost,
            &sign_input,
            &inputs.char_act,
            inputs.char_input.log_size(),
            virtualized_ir,
        );
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        // Combine the LIKE-injected `orig_ind` and `mark` char-domain
        // hints into a single INPUT_LABEL HintDF for the SortNoDup child
        // (`nodup_mark`). SortNoDup's planner then uses the combined
        // table to compute LEX_SORTED_LABEL. All fields stay virtual —
        // the concrete TrackedPolys are still committed at prove time
        // by LIKE's existing pipeline.
        let own = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        let orig_ind_hint = match own.get("__like_orig_ind_plan_hint__") {
            Some(h) => h.clone(),
            None => return Ok(()),
        };
        let mark_hint = match own.get("__like_mark_plan_hint__") {
            Some(h) => h.clone(),
            None => return Ok(()),
        };

        let nodup_hint = build_nodup_mark_input_hint(&orig_ind_hint, &mark_hint)
            .map_err(|e| SnarkError::Artifact(format!("factor placement nodup hint: {e}")))?;

        let mut nodup_payload = match planned_ir.payload_for_node(&self.nodup_mark.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        nodup_payload.insert(nodup::INPUT_LABEL.to_string(), nodup_hint);
        planned_ir.set_payload_for_node(
            self.nodup_mark.id(),
            Some(PayloadStructure::GadgetPayload(nodup_payload)),
        );
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
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let inputs = extract_verifier_inputs(virtualized_ir, id, self.mode, self.pattern.len());
        set_bool_payload_verifier(&self.bool_occurs, &inputs.occurs, virtualized_ir);
        set_bool_payload_verifier(&self.bool_match, &inputs.match_str, virtualized_ir);
        set_bool_payload_verifier(&self.bool_mark, &inputs.mark, virtualized_ir);
        set_broadcast_match_payload_verifier(&self.broadcast_match, &inputs, virtualized_ir);
        set_nodup_mark_payload_verifier(&self.nodup_mark, &inputs, virtualized_ir);
        let gamma = verifier.get_and_append_challenge(b"factor_placement_gamma")?;
        set_lookup_placement_payload_verifier(
            &self.lookup_placement,
            &inputs,
            gamma,
            virtualized_ir,
        );
        if let Some(ref rot_check) = self.att_mask_rot_check {
            set_att_mask_rot_check_payload_verifier(rot_check, &inputs, virtualized_ir);
        }
        if !self.bnd_rot_checks.is_empty() {
            set_bnd_chain_rot_check_payloads_verifier(
                &self.bnd_rot_checks,
                &inputs,
                virtualized_ir,
            );
        }
        // Step 4(e): leftmost check — mirror of the prover side.
        set_bool_payload_verifier(
            &self.bool_leftmost_mask,
            &inputs.leftmost_mask,
            virtualized_ir,
        );
        set_broadcast_start_payload_verifier(&self.broadcast_start, &inputs, virtualized_ir);
        let sign_input = build_leftmost_sign_input_oracle(&inputs);
        set_sign_leftmost_payload_verifier(
            &self.sign_leftmost,
            &sign_input,
            &inputs.char_act,
            inputs.char_input.log_size(),
            virtualized_ir,
        );
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        // Combine the LIKE-injected `orig_ind` and `mark` char-domain
        // hints into a single INPUT_LABEL HintDF for the SortNoDup child
        // (`nodup_mark`). SortNoDup's planner then uses the combined
        // table to compute LEX_SORTED_LABEL. All fields stay virtual —
        // the concrete TrackedPolys are still committed at prove time
        // by LIKE's existing pipeline.
        let own = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        let orig_ind_hint = match own.get("__like_orig_ind_plan_hint__") {
            Some(h) => h.clone(),
            None => return Ok(()),
        };
        let mark_hint = match own.get("__like_mark_plan_hint__") {
            Some(h) => h.clone(),
            None => return Ok(()),
        };

        let nodup_hint = build_nodup_mark_input_hint(&orig_ind_hint, &mark_hint)
            .map_err(|e| SnarkError::Artifact(format!("factor placement nodup hint: {e}")))?;

        let mut nodup_payload = match planned_ir.payload_for_node(&self.nodup_mark.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        nodup_payload.insert(nodup::INPUT_LABEL.to_string(), nodup_hint);
        planned_ir.set_payload_for_node(
            self.nodup_mark.id(),
            Some(PayloadStructure::GadgetPayload(nodup_payload)),
        );
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
        let inputs = extract_prover_inputs(gadget_ready_ir, id, self.mode, self.pattern.len());
        let char_domain = inputs.char_input.log_size();

        // Fingerprint coefficients — sampled per instance. Each successive
        // call with the same tag yields a fresh challenge because the
        // transcript has advanced with prior claims.
        let mut coeffs = Vec::with_capacity(self.pattern.len());
        for _ in 0..self.pattern.len() {
            coeffs.push(prover.get_and_append_challenge(b"factor_placement_r")?);
        }

        // Prefix: att_mask := char-act · bnd (derived).
        // Suffix: att_mask is payload-supplied; the RotationCheck child
        //         proves it equals ρ_{-ℓ}(char-act · bnd).
        // Infix:  att_mask := char-act · (1 - Σ_{δ=1..ℓ-1} bnd(δ)) (derived
        //         from the payload-supplied rotated bnd columns).
        let att_mask = match self.mode {
            Mode::Prefix => resize_poly(&(&inputs.char_act * &inputs.bnd), char_domain),
            Mode::Suffix => inputs
                .att_mask
                .clone()
                .expect("suffix: att_mask must be populated"),
            Mode::Infix => {
                // sum := Σ_{δ=1..ℓ-1} bnd(δ)
                let one_minus_sum = if inputs.rotated_bnds.is_empty() {
                    // ℓ = 1: sum is empty, so 1 - 0 = 1 (constant 1 poly).
                    inputs
                        .bnd
                        .mul_scalar_poly(B::F::zero())
                        .add_scalar_poly(B::F::from(1u64))
                } else {
                    let mut sum = inputs.rotated_bnds[0].clone();
                    for b in inputs.rotated_bnds.iter().skip(1) {
                        sum = &sum + b;
                    }
                    sum.mul_scalar_poly(-B::F::from(1u64))
                        .add_scalar_poly(B::F::from(1u64))
                };
                resize_poly(&(&inputs.char_act * &one_minus_sum), char_domain)
            }
        };

        // diff := Σ r_δ · char^(δ) − pf
        let diff = build_diff_poly::<B>(&inputs.rotated_chars, &self.pattern, &coeffs, char_domain);

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

        let n_m_key = miscellaneous_key(id, gadget_ready_ir.tree(), "n_m");
        prover.add_miscellaneous_field_element(n_m_key, n_m)?;
        prover.add_mv_sumcheck_claim(inputs.mark.id(), n_m)?;
        prover.add_mv_sumcheck_claim(inputs.match_str.id(), n_m)?;

        // Step 4(d) LookupCheck on (match, ind+γ·start) ⊑ (mark, orig-ind+γ·int-ind)
        // is wired as a child gadget via `lookup_placement`; γ is sampled
        // in `initialize_gadgets` (see the comment there).

        // Step 4(e): leftmost check — Zerocheck on
        //   occurs · leftmost_mask · match_broadcast = 0.
        // Combined with the BoolCheck on `mask`, the BroadcastCheck on
        // `(start, start')`, and the NonNegative Sign on
        //   mask · (start' - int_ind - 1) + (1 - mask) · (int_ind - start')
        // — all wired in `initialize_gadgets` — this forces `mask[c] = 1
        // iff int_ind[c] < start'[c]`, so any candidate occurrence to the
        // left of the mark contradicts the zerocheck and is rejected.
        {
            let masked = &inputs.occurs * &inputs.leftmost_mask;
            let claim = &resize_poly(&masked, char_domain) * &inputs.match_broadcast;
            prover.add_mv_zerocheck_claim(resize_poly(&claim, char_domain).id())?;
        }

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
        let inputs = extract_verifier_inputs(gadget_ready_ir, id, self.mode, self.pattern.len());
        let char_domain = inputs.char_input.log_size();

        let mut coeffs = Vec::with_capacity(self.pattern.len());
        for _ in 0..self.pattern.len() {
            coeffs.push(verifier.get_and_append_challenge(b"factor_placement_r")?);
        }

        let att_mask = match self.mode {
            Mode::Prefix => resize_oracle(&(&inputs.char_act * &inputs.bnd), char_domain),
            Mode::Suffix => inputs
                .att_mask
                .clone()
                .expect("suffix: att_mask must be populated"),
            Mode::Infix => {
                let one_minus_sum = if inputs.rotated_bnds.is_empty() {
                    inputs
                        .bnd
                        .mul_scalar_oracle(B::F::zero())
                        .add_scalar_oracle(B::F::from(1u64))
                } else {
                    let mut sum = inputs.rotated_bnds[0].clone();
                    for b in inputs.rotated_bnds.iter().skip(1) {
                        sum = &sum + b;
                    }
                    sum.mul_scalar_oracle(-B::F::from(1u64))
                        .add_scalar_oracle(B::F::from(1u64))
                };
                resize_oracle(&(&inputs.char_act * &one_minus_sum), char_domain)
            }
        };

        let diff =
            build_diff_oracle::<B>(&inputs.rotated_chars, &self.pattern, &coeffs, char_domain);

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

        let n_m_key = miscellaneous_key(id, gadget_ready_ir.tree(), "n_m");
        let n_m = verifier.miscellaneous_field_element(&n_m_key)?;
        verifier.add_mv_sumcheck_claim(inputs.mark.id(), n_m);
        verifier.add_mv_sumcheck_claim(inputs.match_str.id(), n_m);

        // Step 4(d) is wired via `lookup_placement`; `start` and `int-ind`
        // are used there.

        // Step 4(e): leftmost check — Zerocheck mirroring the prover side.
        {
            let masked = &inputs.occurs * &inputs.leftmost_mask;
            let claim = &resize_oracle(&masked, char_domain) * &inputs.match_broadcast;
            verifier.add_mv_zerocheck_claim(resize_oracle(&claim, char_domain).id());
        }

        Ok(())
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

//! Composite gadget for paper §6.1 PIOP 7 Sweep Factors.
//!
//! Given a factor list `[(str_1, mode_1), …, (str_t, mode_t)]`, base
//! char/string tables, and initial activators `(alive_c_0, alive_h_0)`
//! (typically the outputs of Length Filtering), this gadget places each
//! factor sequentially and threads activator state between rounds so
//! that factor `j+1` may only match char positions past factor `j`'s
//! mark and only inside strings that matched factor `j`.
//!
//! # Per-round pipeline for factor `j` (0-indexed)
//!
//! 1. **Rotation chain** — verify the payload-supplied rotated char
//!    columns `char^{(1)}_j, …, char^{(k_j−1)}_j` against `char` via
//!    `k_j − 1` `RotationCheck(Left, shift=1)` children on
//!    `(char^{(δ−1)}_j, char^{(δ)}_j)`; `char^{(0)}_j` is `char`
//!    itself.
//! 2. **Activator rebuild** — rebuild `CHAR_INPUT` with activator
//!    `alive_c_{j-1}` and `STR_INPUT` with activator `alive_h_{j-1}`;
//!    both activators are virtual polys (products of prior rounds'
//!    witnesses) so the verifier reproduces them directly.
//! 3. **FactorPlacement(p_j)** — one child; consumes the rebuilt inputs
//!    plus the per-factor payload (occurs / match / mark / start /
//!    match_broadcast / start_broadcast / leftmost_mask + mode-specific
//!    att_mask / rotated_bnd).
//! 4. **Past check** (only for `j < t − 1`) — prover commits `past_j`, a
//!    boolean char-level column with `past_j[c] = 1 iff int_ind[c] >
//!    start'_j[c]`. Discharged by:
//!    - `BoolCheck` on `past_j`,
//!    - `SignNode(NonNegative)` on the mask-selected difference
//!      `past_j · (int_ind − start'_j − 1) + (1 − past_j) ·
//!      (start'_j − int_ind)`, activated by `alive_c_{j-1}`.
//!
//!    Note: `start'_j` (the char-level broadcast of `start_j`) is
//!    already committed and verified inside `FactorPlacement(p_j)` — we
//!    reuse it here without an extra `BroadcastCheck`.
//! 5. **Activator update** — `alive_c_j := alive_c_{j-1} · past_j`
//!    (chars past the j-th mark stay alive), `alive_h_j := match_j`
//!    (strings that matched factor j stay alive).
//!
//! # Output
//!
//! The final alive_h_{t-1} = `match_{t-1}` is exposed to callers via the
//! per-factor `MATCH_LABEL_{t-1}` in the input payload. Downstream
//! composites (e.g. MCPM) enforce their own verdict zerocheck against
//! this column.
//!
//! # Payload structure
//!
//! - `CHAR_INPUT_LABEL` / `STR_INPUT_LABEL` — base tables. `STR_INPUT`
//!   carries the *initial* string activator `alive_h_0` (typically
//!   `a^{old'}` from LFC). `CHAR_INPUT` carries the *initial* char
//!   activator `alive_c_0` (typically `char-act^{old'}` from LFC).
//! - Per factor `j` (0-indexed), via [`factor_label`]`(j, …)`:
//!   - `"rotated_char"` — `k_j` char-level columns `char^{(0)}_j..char^{(k_j−1)}_j`.
//!   - `"occurs"`, `"match"`, `"mark"`, `"start"`, `"match_broadcast"`,
//!     `"start_broadcast"`, `"leftmost_mask"` — FactorPlacement
//!     witnesses (see that module's docs).
//!   - `"att_mask"` — suffix mode only.
//!   - `"rotated_bnd"` — infix mode only when `k_j ≥ 2`.
//!   - `"past"` — for `j < t − 1` only. Boolean char-level column.

use std::marker::PhantomData;
use std::sync::Arc;

use arithmetic::{ACTIVATOR_FIELD, table::TrackedTable, table_oracle::TrackedTableOracle};
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
            utils::{bool as bool_check, factor_placement, rotation_check, sign},
        },
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub use factor_placement::Mode;

pub const CHAR_INPUT_LABEL: &str = "__char_input__";
pub const STR_INPUT_LABEL: &str = "__str_input__";

/// Parse a SQL LIKE pattern into a factor list suitable for
/// [`GadgetNode::new`].
///
/// The pattern is a byte-oriented ASCII string; wildcards are `%`
/// (zero or more chars) and `_` (single char). The **single-char `_`
/// wildcard is not supported** yet — parsing rejects any pattern that
/// contains it. Escape sequences (`\%`, `\_`) are treated as literals.
///
/// The resulting factor list is derived by splitting on `%`:
/// - A leading non-empty segment before the first `%` becomes a
///   `Prefix` factor.
/// - A trailing non-empty segment after the last `%` becomes a
///   `Suffix` factor.
/// - Every other non-empty segment (between two `%`s) becomes an
///   `Infix` factor.
/// - Empty segments (adjacent `%`s, or `%` at either end) are dropped
///   from the factor list — they represent unconstrained regions.
///
/// The empty pattern and the pattern `"%"` both return `Ok(vec![])`,
/// which callers should special-case (they match all strings).
///
/// Examples:
/// - `"abc%"` → `[(abc, Prefix)]`
/// - `"%abc"` → `[(abc, Suffix)]`
/// - `"%abc%"` → `[(abc, Infix)]`
/// - `"foo%bar%baz"` → `[(foo, Prefix), (bar, Infix), (baz, Suffix)]`
/// - `"%foo%bar%"` → `[(foo, Infix), (bar, Infix)]`
///
/// **Known limitation**: a wildcard-free pattern (e.g. `"abc"`) parses
/// to `[(abc, Prefix)]`, which — combined with the LFC threshold — is
/// equivalent to `LIKE 'abc%'`, NOT strict equality. Callers wanting
/// `col = 'abc'` semantics should lower to a direct equality expression
/// rather than routing through `parse_like_pattern`.
pub fn parse_like_pattern<F: ark_ff::PrimeField>(
    pattern: &str,
) -> Result<Vec<(Vec<F>, Mode)>, String> {
    if pattern.is_empty() {
        return Ok(Vec::new());
    }
    // Reject `_` (single-char wildcard) until we support it.
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'_' {
            return Err("LIKE `_` (single-char wildcard) is not supported yet".to_string());
        }
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            // Skip escape target; escapes are treated as literals below too.
            i += 2;
            continue;
        }
        i += 1;
    }

    // Split on unescaped `%`, treating `\%` as a literal.
    let mut segments: Vec<Vec<u8>> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() && bytes[i + 1] == b'%' {
            current.push(b'%');
            i += 2;
        } else if bytes[i] == b'%' {
            segments.push(std::mem::take(&mut current));
            i += 1;
        } else {
            current.push(bytes[i]);
            i += 1;
        }
    }
    segments.push(current);

    let starts_with_wild = segments.first().map(|s| s.is_empty()).unwrap_or(true);
    let ends_with_wild = segments.last().map(|s| s.is_empty()).unwrap_or(true);

    let non_empty: Vec<Vec<u8>> = segments.into_iter().filter(|s| !s.is_empty()).collect();
    if non_empty.is_empty() {
        // Pattern is all wildcards, e.g. `"%"` or `"%%"`.
        return Ok(Vec::new());
    }

    let last_idx = non_empty.len() - 1;
    let mut factors: Vec<(Vec<F>, Mode)> = Vec::with_capacity(non_empty.len());
    for (idx, seg) in non_empty.into_iter().enumerate() {
        let mode = if idx == 0 && !starts_with_wild {
            Mode::Prefix
        } else if idx == last_idx && !ends_with_wild {
            Mode::Suffix
        } else {
            Mode::Infix
        };
        let literal: Vec<F> = seg.into_iter().map(|b| F::from(b as u64)).collect();
        factors.push((literal, mode));
    }
    Ok(factors)
}

/// Payload label for the per-factor `name` slot at factor index `j`
/// (0-indexed). Slots: `"rotated_char"`, `"occurs"`, `"match"`, `"mark"`,
/// `"start"`, `"match_broadcast"`, `"start_broadcast"`, `"leftmost_mask"`,
/// `"att_mask"` (suffix only), `"rotated_bnd"` (infix, k ≥ 2 only), and
/// `"past"` (for `j < t − 1` only).
pub fn factor_label(j: usize, name: &str) -> String {
    format!("__f{j}_{name}__")
}

fn u64_field(name: &str) -> FieldRef {
    Arc::new(Field::new(name, DataType::UInt64, false))
}
fn bool_field() -> FieldRef {
    Arc::new(Field::new("data", DataType::Boolean, false))
}
fn sign_input_field() -> FieldRef {
    Arc::new(Field::new("__past_sign_input__", DataType::Int64, false))
}

fn resize_poly<B: SnarkBackend>(p: &TrackedPoly<B>, log_size: usize) -> TrackedPoly<B> {
    TrackedPoly::new(p.id_or_const(), log_size, p.tracker())
}
fn resize_oracle<B: SnarkBackend>(o: &TrackedOracle<B>, log_size: usize) -> TrackedOracle<B> {
    TrackedOracle::new(o.id_or_const(), o.tracker(), log_size)
}

/// Sweep Factors gadget over an ordered list of `(pattern, mode)` factors.
pub struct GadgetNode<B: SnarkBackend> {
    factors: Vec<(Vec<B::F>, Mode)>,
    // One FactorPlacement child per factor.
    factor_placements: Vec<Arc<Node<B>>>,
    // Rotation chain per factor: `k_j − 1` `RotationCheck(Left, 1)` children.
    rotation_chains: Vec<Vec<Arc<Node<B>>>>,
    // Past-check children (one set per inter-factor step, i.e. `t − 1`
    // sets when `t ≥ 2`; empty for `t = 1`).
    bool_pasts: Vec<Arc<Node<B>>>,
    sign_pasts: Vec<Arc<Node<B>>>,
    _phantom: PhantomData<B>,
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(factors: Vec<(Vec<B::F>, Mode)>) -> Self {
        Self::new_with_nodup_mode(factors, crate::irs::nodes::utils::nodup::Mode::SortBased)
    }

    /// Test-facing constructor that lets callers pick the nodup_mark
    /// mode inside each nested FactorPlacement. Production callers
    /// should use [`Self::new`] (defaults to `SortBased`, required for
    /// LIKE's plan-time hint pipeline). Test harnesses that skip
    /// `initialize_gadget_plans` need `BezoutBased`.
    pub fn new_with_nodup_mode(
        factors: Vec<(Vec<B::F>, Mode)>,
        nodup_mode: crate::irs::nodes::utils::nodup::Mode,
    ) -> Self {
        assert!(
            !factors.is_empty(),
            "SweepFactors: factor list must be non-empty"
        );
        for (pat, _) in &factors {
            assert!(
                !pat.is_empty(),
                "SweepFactors: each factor pattern must be non-empty"
            );
        }
        let t = factors.len();

        let factor_placements: Vec<Arc<Node<B>>> = factors
            .iter()
            .map(|(pat, mode)| {
                Arc::new(Node::<B>::Gadget(Arc::new(
                    factor_placement::GadgetNode::new_with_nodup_mode(
                        pat.clone(),
                        *mode,
                        nodup_mode,
                    ),
                )))
            })
            .collect();

        let rotation_chains: Vec<Vec<Arc<Node<B>>>> = factors
            .iter()
            .map(|(pat, _)| {
                (1..pat.len())
                    .map(|_| {
                        Arc::new(Node::<B>::Gadget(Arc::new(
                            rotation_check::GadgetNode::new(1, rotation_check::Direction::Left),
                        )))
                    })
                    .collect()
            })
            .collect();

        let bool_pasts: Vec<Arc<Node<B>>> = (0..t.saturating_sub(1))
            .map(|_| Arc::new(Node::<B>::Gadget(Arc::new(bool_check::GadgetNode::new()))))
            .collect();

        let sign_pasts: Vec<Arc<Node<B>>> = (0..t.saturating_sub(1))
            .map(|_| {
                Arc::new(Node::<B>::Gadget(Arc::new(sign::SignNode::new(
                    sign::SignConfig::Uniform(sign::Sign::NonNegative),
                ))))
            })
            .collect();

        Self {
            factors,
            factor_placements,
            rotation_chains,
            bool_pasts,
            sign_pasts,
            _phantom: PhantomData,
        }
    }

    pub fn num_factors(&self) -> usize {
        self.factors.len()
    }
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        format!("SweepFactors(t={})", self.factors.len())
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
        let mut out: Vec<Arc<Node<B>>> = Vec::new();
        for (fp, chain) in self
            .factor_placements
            .iter()
            .zip(self.rotation_chains.iter())
        {
            out.extend(chain.iter().cloned());
            out.push(fp.clone());
        }
        for (bp, sp) in self.bool_pasts.iter().zip(self.sign_pasts.iter()) {
            out.push(bp.clone());
            out.push(sp.clone());
        }
        out
    }
}

// ---- Payload extraction ----

struct FactorProver<B: SnarkBackend> {
    rotated_chars: Vec<TrackedPoly<B>>,
    occurs: TrackedTable<B>,
    match_str: TrackedTable<B>,
    mark: TrackedTable<B>,
    start: TrackedTable<B>,
    match_broadcast: TrackedTable<B>,
    start_broadcast: TrackedTable<B>,
    leftmost_mask: TrackedTable<B>,
    att_mask: Option<TrackedTable<B>>,
    rotated_bnd: Option<TrackedTable<B>>,
    // Convenience: the single data column of `match_str`, `start_broadcast`, `past`.
    match_col: TrackedPoly<B>,
    start_broadcast_col: TrackedPoly<B>,
    past_col: Option<TrackedPoly<B>>,
}

struct FactorVerifier<B: SnarkBackend> {
    rotated_chars: Vec<TrackedOracle<B>>,
    occurs: TrackedTableOracle<B>,
    match_str: TrackedTableOracle<B>,
    mark: TrackedTableOracle<B>,
    start: TrackedTableOracle<B>,
    match_broadcast: TrackedTableOracle<B>,
    start_broadcast: TrackedTableOracle<B>,
    leftmost_mask: TrackedTableOracle<B>,
    att_mask: Option<TrackedTableOracle<B>>,
    rotated_bnd: Option<TrackedTableOracle<B>>,
    match_col: TrackedOracle<B>,
    start_broadcast_col: TrackedOracle<B>,
    past_col: Option<TrackedOracle<B>>,
}

fn extract_factor_prover<B: SnarkBackend>(
    payload: &IndexMap<String, TrackedTable<B>>,
    j: usize,
    pattern_len: usize,
    mode: Mode,
    has_past: bool,
) -> FactorProver<B> {
    let rotated = payload
        .get(&factor_label(j, "rotated_char"))
        .unwrap_or_else(|| panic!("SweepFactors: missing rotated_char for factor {j}"));
    let rotated_indices = rotated.data_tracked_polys_indices();
    assert_eq!(
        rotated_indices.len(),
        pattern_len,
        "SweepFactors: factor {j} rotated_char must have {pattern_len} columns"
    );
    let rotated_chars: Vec<TrackedPoly<B>> = rotated_indices
        .into_iter()
        .map(|idx| rotated.tracked_col_by_ind(idx).data_tracked_poly())
        .collect();

    let occurs = payload
        .get(&factor_label(j, "occurs"))
        .unwrap_or_else(|| panic!("SweepFactors: missing occurs for factor {j}"))
        .clone();
    let match_str = payload
        .get(&factor_label(j, "match"))
        .unwrap_or_else(|| panic!("SweepFactors: missing match for factor {j}"))
        .clone();
    let mark = payload
        .get(&factor_label(j, "mark"))
        .unwrap_or_else(|| panic!("SweepFactors: missing mark for factor {j}"))
        .clone();
    let start = payload
        .get(&factor_label(j, "start"))
        .unwrap_or_else(|| panic!("SweepFactors: missing start for factor {j}"))
        .clone();
    let match_broadcast = payload
        .get(&factor_label(j, "match_broadcast"))
        .unwrap_or_else(|| panic!("SweepFactors: missing match_broadcast for factor {j}"))
        .clone();
    let start_broadcast = payload
        .get(&factor_label(j, "start_broadcast"))
        .unwrap_or_else(|| panic!("SweepFactors: missing start_broadcast for factor {j}"))
        .clone();
    let leftmost_mask = payload
        .get(&factor_label(j, "leftmost_mask"))
        .unwrap_or_else(|| panic!("SweepFactors: missing leftmost_mask for factor {j}"))
        .clone();

    let att_mask = match mode {
        Mode::Suffix => Some(
            payload
                .get(&factor_label(j, "att_mask"))
                .unwrap_or_else(|| panic!("SweepFactors: missing att_mask for suffix factor {j}"))
                .clone(),
        ),
        _ => None,
    };
    let rotated_bnd = match mode {
        Mode::Infix if pattern_len >= 2 => Some(
            payload
                .get(&factor_label(j, "rotated_bnd"))
                .unwrap_or_else(|| {
                    panic!("SweepFactors: missing rotated_bnd for infix factor {j} (k ≥ 2)")
                })
                .clone(),
        ),
        _ => None,
    };
    let past = if has_past {
        Some(
            payload
                .get(&factor_label(j, "past"))
                .unwrap_or_else(|| panic!("SweepFactors: missing past for factor {j}"))
                .clone(),
        )
    } else {
        None
    };

    let match_col = single_col(&match_str);
    let start_broadcast_col = single_col(&start_broadcast);
    let past_col = past.as_ref().map(single_col);
    let _ = past;

    FactorProver {
        rotated_chars,
        occurs,
        match_str,
        mark,
        start,
        match_broadcast,
        start_broadcast,
        leftmost_mask,
        att_mask,
        rotated_bnd,
        match_col,
        start_broadcast_col,
        past_col,
    }
}

fn extract_factor_verifier<B: SnarkBackend>(
    payload: &IndexMap<String, TrackedTableOracle<B>>,
    j: usize,
    pattern_len: usize,
    mode: Mode,
    has_past: bool,
) -> FactorVerifier<B> {
    let rotated = payload
        .get(&factor_label(j, "rotated_char"))
        .unwrap_or_else(|| panic!("SweepFactors: missing rotated_char for factor {j}"));
    let rotated_indices = rotated.data_tracked_oracles_indices();
    assert_eq!(
        rotated_indices.len(),
        pattern_len,
        "SweepFactors: factor {j} rotated_char must have {pattern_len} columns"
    );
    let rotated_chars: Vec<TrackedOracle<B>> = rotated_indices
        .into_iter()
        .map(|idx| rotated.tracked_col_oracle_by_ind(idx).data_tracked_oracle())
        .collect();

    let occurs = payload
        .get(&factor_label(j, "occurs"))
        .unwrap_or_else(|| panic!("SweepFactors: missing occurs for factor {j}"))
        .clone();
    let match_str = payload
        .get(&factor_label(j, "match"))
        .unwrap_or_else(|| panic!("SweepFactors: missing match for factor {j}"))
        .clone();
    let mark = payload
        .get(&factor_label(j, "mark"))
        .unwrap_or_else(|| panic!("SweepFactors: missing mark for factor {j}"))
        .clone();
    let start = payload
        .get(&factor_label(j, "start"))
        .unwrap_or_else(|| panic!("SweepFactors: missing start for factor {j}"))
        .clone();
    let match_broadcast = payload
        .get(&factor_label(j, "match_broadcast"))
        .unwrap_or_else(|| panic!("SweepFactors: missing match_broadcast for factor {j}"))
        .clone();
    let start_broadcast = payload
        .get(&factor_label(j, "start_broadcast"))
        .unwrap_or_else(|| panic!("SweepFactors: missing start_broadcast for factor {j}"))
        .clone();
    let leftmost_mask = payload
        .get(&factor_label(j, "leftmost_mask"))
        .unwrap_or_else(|| panic!("SweepFactors: missing leftmost_mask for factor {j}"))
        .clone();

    let att_mask = match mode {
        Mode::Suffix => Some(
            payload
                .get(&factor_label(j, "att_mask"))
                .unwrap_or_else(|| panic!("SweepFactors: missing att_mask for suffix factor {j}"))
                .clone(),
        ),
        _ => None,
    };
    let rotated_bnd = match mode {
        Mode::Infix if pattern_len >= 2 => Some(
            payload
                .get(&factor_label(j, "rotated_bnd"))
                .unwrap_or_else(|| {
                    panic!("SweepFactors: missing rotated_bnd for infix factor {j} (k ≥ 2)")
                })
                .clone(),
        ),
        _ => None,
    };
    let past = if has_past {
        Some(
            payload
                .get(&factor_label(j, "past"))
                .unwrap_or_else(|| panic!("SweepFactors: missing past for factor {j}"))
                .clone(),
        )
    } else {
        None
    };

    let match_col = single_col_oracle(&match_str);
    let start_broadcast_col = single_col_oracle(&start_broadcast);
    let past_col = past.as_ref().map(single_col_oracle);
    let _ = past;

    FactorVerifier {
        rotated_chars,
        occurs,
        match_str,
        mark,
        start,
        match_broadcast,
        start_broadcast,
        leftmost_mask,
        att_mask,
        rotated_bnd,
        match_col,
        start_broadcast_col,
        past_col,
    }
}

fn single_col<B: SnarkBackend>(t: &TrackedTable<B>) -> TrackedPoly<B> {
    let idx = t.data_tracked_polys_indices()[0];
    t.tracked_col_by_ind(idx).data_tracked_poly()
}

fn single_col_oracle<B: SnarkBackend>(t: &TrackedTableOracle<B>) -> TrackedOracle<B> {
    let idx = t.data_tracked_oracles_indices()[0];
    t.tracked_col_oracle_by_ind(idx).data_tracked_oracle()
}

// ---- Child payload wiring ----

fn set_rotation_chain_payload_prover<B: SnarkBackend>(
    checks: &[Arc<Node<B>>],
    rotated_chars: &[TrackedPoly<B>],
    char_domain: usize,
    ir: &mut GadgetReadyIr<B>,
) {
    // `char^{(0)}` is the base char column and is trusted to match the
    // char_input's `char` column at the caller's layer. The rotation
    // chain proves `char^{(δ)} = ρ_{-1}(char^{(δ-1)})` for δ = 1..k-1.
    assert_eq!(
        checks.len() + 1,
        rotated_chars.len(),
        "SweepFactors: rotation chain size must be k - 1"
    );
    for (delta, check) in checks.iter().enumerate() {
        let left_poly = rotated_chars[delta].clone();
        let right_poly = rotated_chars[delta + 1].clone();

        let left_f = u64_field(&format!("rotated_char_{delta}"));
        let mut left_polys = IndexMap::new();
        left_polys.insert(left_f.clone(), left_poly);
        let left = TrackedTable::new(
            Some(Schema::new(vec![left_f.as_ref().clone()])),
            left_polys,
            char_domain,
        );

        let right_f = u64_field(&format!("rotated_char_{}", delta + 1));
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

fn set_rotation_chain_payload_verifier<B: SnarkBackend>(
    checks: &[Arc<Node<B>>],
    rotated_chars: &[TrackedOracle<B>],
    char_domain: usize,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    assert_eq!(
        checks.len() + 1,
        rotated_chars.len(),
        "SweepFactors: rotation chain size must be k - 1"
    );
    for (delta, check) in checks.iter().enumerate() {
        let left_oracle = rotated_chars[delta].clone();
        let right_oracle = rotated_chars[delta + 1].clone();

        let left_f = u64_field(&format!("rotated_char_{delta}"));
        let mut left_oracles = IndexMap::new();
        left_oracles.insert(left_f.clone(), left_oracle);
        let left = TrackedTableOracle::new(
            Some(Schema::new(vec![left_f.as_ref().clone()])),
            left_oracles,
            char_domain,
        );

        let right_f = u64_field(&format!("rotated_char_{}", delta + 1));
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

fn set_bool_past_payload_prover<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    past: &TrackedPoly<B>,
    ir: &mut GadgetReadyIr<B>,
) {
    let mut polys = IndexMap::new();
    polys.insert(bool_field(), past.clone());
    let schema = Schema::new(vec![bool_field().as_ref().clone()]);
    let table = TrackedTable::new(Some(schema), polys, past.log_size());
    let mut payload = IndexMap::new();
    payload.insert(bool_check::TABLE_LABEL.to_string(), table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

fn set_bool_past_payload_verifier<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    past: &TrackedOracle<B>,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let mut oracles = IndexMap::new();
    oracles.insert(bool_field(), past.clone());
    let schema = Schema::new(vec![bool_field().as_ref().clone()]);
    let table = TrackedTableOracle::new(Some(schema), oracles, past.log_size());
    let mut payload = IndexMap::new();
    payload.insert(bool_check::TABLE_LABEL.to_string(), table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

fn set_sign_past_payload_prover<B: SnarkBackend>(
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

fn set_sign_past_payload_verifier<B: SnarkBackend>(
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

/// Rebuild the base char_input with a fresh activator, preserving the
/// four data columns `char, orig_ind, int_ind, bnd` in the same order.
fn rebuild_char_input_prover<B: SnarkBackend>(
    char_input: &TrackedTable<B>,
    activator: TrackedPoly<B>,
) -> TrackedTable<B> {
    let data_indices = char_input.data_tracked_polys_indices();
    assert_eq!(
        data_indices.len(),
        4,
        "SweepFactors: CHAR_INPUT expects 4 data columns"
    );
    let char_col = char_input
        .tracked_col_by_ind(data_indices[0])
        .data_tracked_poly();
    let orig_ind = char_input
        .tracked_col_by_ind(data_indices[1])
        .data_tracked_poly();
    let int_ind = char_input
        .tracked_col_by_ind(data_indices[2])
        .data_tracked_poly();
    let bnd = char_input
        .tracked_col_by_ind(data_indices[3])
        .data_tracked_poly();

    let char_f = u64_field("char");
    let orig_ind_f = u64_field("orig_ind");
    let int_ind_f = u64_field("int_ind");
    let bnd_f = u64_field("bnd");

    let mut polys = IndexMap::new();
    polys.insert(char_f.clone(), char_col);
    polys.insert(orig_ind_f.clone(), orig_ind);
    polys.insert(int_ind_f.clone(), int_ind);
    polys.insert(bnd_f.clone(), bnd);
    polys.insert(ACTIVATOR_FIELD.clone(), activator);
    let schema = Schema::new(vec![
        char_f.as_ref().clone(),
        orig_ind_f.as_ref().clone(),
        int_ind_f.as_ref().clone(),
        bnd_f.as_ref().clone(),
    ]);
    TrackedTable::new(Some(schema), polys, char_input.log_size())
}

fn rebuild_char_input_verifier<B: SnarkBackend>(
    char_input: &TrackedTableOracle<B>,
    activator: TrackedOracle<B>,
) -> TrackedTableOracle<B> {
    let data_indices = char_input.data_tracked_oracles_indices();
    assert_eq!(
        data_indices.len(),
        4,
        "SweepFactors: CHAR_INPUT expects 4 data columns"
    );
    let char_col = char_input
        .tracked_col_oracle_by_ind(data_indices[0])
        .data_tracked_oracle();
    let orig_ind = char_input
        .tracked_col_oracle_by_ind(data_indices[1])
        .data_tracked_oracle();
    let int_ind = char_input
        .tracked_col_oracle_by_ind(data_indices[2])
        .data_tracked_oracle();
    let bnd = char_input
        .tracked_col_oracle_by_ind(data_indices[3])
        .data_tracked_oracle();

    let char_f = u64_field("char");
    let orig_ind_f = u64_field("orig_ind");
    let int_ind_f = u64_field("int_ind");
    let bnd_f = u64_field("bnd");

    let mut oracles = IndexMap::new();
    oracles.insert(char_f.clone(), char_col);
    oracles.insert(orig_ind_f.clone(), orig_ind);
    oracles.insert(int_ind_f.clone(), int_ind);
    oracles.insert(bnd_f.clone(), bnd);
    oracles.insert(ACTIVATOR_FIELD.clone(), activator);
    let schema = Schema::new(vec![
        char_f.as_ref().clone(),
        orig_ind_f.as_ref().clone(),
        int_ind_f.as_ref().clone(),
        bnd_f.as_ref().clone(),
    ]);
    TrackedTableOracle::new(Some(schema), oracles, char_input.log_size())
}

fn rebuild_str_input_prover<B: SnarkBackend>(
    str_input: &TrackedTable<B>,
    activator: TrackedPoly<B>,
) -> TrackedTable<B> {
    let data_indices = str_input.data_tracked_polys_indices();
    assert!(
        !data_indices.is_empty(),
        "SweepFactors: STR_INPUT must have at least ind"
    );
    let ind = str_input
        .tracked_col_by_ind(data_indices[0])
        .data_tracked_poly();

    let ind_f = u64_field("ind");
    let mut polys = IndexMap::new();
    polys.insert(ind_f.clone(), ind);
    polys.insert(ACTIVATOR_FIELD.clone(), activator);
    let schema = Schema::new(vec![ind_f.as_ref().clone()]);
    TrackedTable::new(Some(schema), polys, str_input.log_size())
}

fn rebuild_str_input_verifier<B: SnarkBackend>(
    str_input: &TrackedTableOracle<B>,
    activator: TrackedOracle<B>,
) -> TrackedTableOracle<B> {
    let data_indices = str_input.data_tracked_oracles_indices();
    assert!(
        !data_indices.is_empty(),
        "SweepFactors: STR_INPUT must have at least ind"
    );
    let ind = str_input
        .tracked_col_oracle_by_ind(data_indices[0])
        .data_tracked_oracle();

    let ind_f = u64_field("ind");
    let mut oracles = IndexMap::new();
    oracles.insert(ind_f.clone(), ind);
    oracles.insert(ACTIVATOR_FIELD.clone(), activator);
    let schema = Schema::new(vec![ind_f.as_ref().clone()]);
    TrackedTableOracle::new(Some(schema), oracles, str_input.log_size())
}

/// Forward the per-factor payload into the FactorPlacement child's
/// payload map, using the labels FactorPlacement expects.
fn set_factor_placement_payload_prover<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    factor: &FactorProver<B>,
    char_input: TrackedTable<B>,
    str_input: TrackedTable<B>,
    ir: &mut GadgetReadyIr<B>,
) {
    // The rotated_char table for FactorPlacement carries all k columns
    // without an activator; rebuild it from the individual polys.
    let char_domain = char_input.log_size();
    let rot_cols: Vec<(FieldRef, TrackedPoly<B>)> = factor
        .rotated_chars
        .iter()
        .enumerate()
        .map(|(delta, p)| (u64_field(&format!("char_{delta}")), p.clone()))
        .collect();
    let rot_schema = Schema::new(
        (0..factor.rotated_chars.len())
            .map(|d| Field::new(format!("char_{d}"), DataType::UInt64, false))
            .collect::<Vec<_>>(),
    );
    let mut rot_polys = IndexMap::new();
    for (f, p) in rot_cols {
        rot_polys.insert(f, p);
    }
    let rotated = TrackedTable::new(Some(rot_schema), rot_polys, char_domain);

    let mut child = IndexMap::new();
    child.insert(factor_placement::CHAR_INPUT_LABEL.to_string(), char_input);
    child.insert(factor_placement::STR_INPUT_LABEL.to_string(), str_input);
    child.insert(factor_placement::ROTATED_CHAR_LABEL.to_string(), rotated);
    child.insert(
        factor_placement::OCCURS_LABEL.to_string(),
        factor.occurs.clone(),
    );
    child.insert(
        factor_placement::MATCH_LABEL.to_string(),
        factor.match_str.clone(),
    );
    child.insert(
        factor_placement::MARK_LABEL.to_string(),
        factor.mark.clone(),
    );
    child.insert(
        factor_placement::START_LABEL.to_string(),
        factor.start.clone(),
    );
    child.insert(
        factor_placement::MATCH_BROADCAST_LABEL.to_string(),
        factor.match_broadcast.clone(),
    );
    child.insert(
        factor_placement::START_BROADCAST_LABEL.to_string(),
        factor.start_broadcast.clone(),
    );
    child.insert(
        factor_placement::LEFTMOST_MASK_LABEL.to_string(),
        factor.leftmost_mask.clone(),
    );
    if let Some(ref am) = factor.att_mask {
        child.insert(factor_placement::ATT_MASK_LABEL.to_string(), am.clone());
    }
    if let Some(ref rb) = factor.rotated_bnd {
        child.insert(factor_placement::ROTATED_BND_LABEL.to_string(), rb.clone());
    }
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(child)));
}

fn set_factor_placement_payload_verifier<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    factor: &FactorVerifier<B>,
    char_input: TrackedTableOracle<B>,
    str_input: TrackedTableOracle<B>,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let char_domain = char_input.log_size();
    let rot_cols: Vec<(FieldRef, TrackedOracle<B>)> = factor
        .rotated_chars
        .iter()
        .enumerate()
        .map(|(delta, p)| (u64_field(&format!("char_{delta}")), p.clone()))
        .collect();
    let rot_schema = Schema::new(
        (0..factor.rotated_chars.len())
            .map(|d| Field::new(format!("char_{d}"), DataType::UInt64, false))
            .collect::<Vec<_>>(),
    );
    let mut rot_oracles = IndexMap::new();
    for (f, p) in rot_cols {
        rot_oracles.insert(f, p);
    }
    let rotated = TrackedTableOracle::new(Some(rot_schema), rot_oracles, char_domain);

    let mut child = IndexMap::new();
    child.insert(factor_placement::CHAR_INPUT_LABEL.to_string(), char_input);
    child.insert(factor_placement::STR_INPUT_LABEL.to_string(), str_input);
    child.insert(factor_placement::ROTATED_CHAR_LABEL.to_string(), rotated);
    child.insert(
        factor_placement::OCCURS_LABEL.to_string(),
        factor.occurs.clone(),
    );
    child.insert(
        factor_placement::MATCH_LABEL.to_string(),
        factor.match_str.clone(),
    );
    child.insert(
        factor_placement::MARK_LABEL.to_string(),
        factor.mark.clone(),
    );
    child.insert(
        factor_placement::START_LABEL.to_string(),
        factor.start.clone(),
    );
    child.insert(
        factor_placement::MATCH_BROADCAST_LABEL.to_string(),
        factor.match_broadcast.clone(),
    );
    child.insert(
        factor_placement::START_BROADCAST_LABEL.to_string(),
        factor.start_broadcast.clone(),
    );
    child.insert(
        factor_placement::LEFTMOST_MASK_LABEL.to_string(),
        factor.leftmost_mask.clone(),
    );
    if let Some(ref am) = factor.att_mask {
        child.insert(factor_placement::ATT_MASK_LABEL.to_string(), am.clone());
    }
    if let Some(ref rb) = factor.rotated_bnd {
        child.insert(factor_placement::ROTATED_BND_LABEL.to_string(), rb.clone());
    }
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(child)));
}

/// Build the derived `sign_input` polynomial for the per-factor past
/// check:
///   `past · (int_ind − start' − 1) + (1 − past) · (start' − int_ind)`
/// Non-negative iff `past` truthfully indicates `int_ind > start'`.
fn build_past_sign_input_poly<B: SnarkBackend>(
    past: &TrackedPoly<B>,
    int_ind: &TrackedPoly<B>,
    start_broadcast: &TrackedPoly<B>,
    log_size: usize,
) -> TrackedPoly<B> {
    let int_minus_start = int_ind - start_broadcast;
    let int_minus_start_minus_one = int_minus_start.sub_scalar_poly(B::F::from(1u64));
    let start_minus_int = start_broadcast - int_ind;

    let term1 = past * &int_minus_start_minus_one;
    let one_minus_past = past
        .mul_scalar_poly(-B::F::from(1u64))
        .add_scalar_poly(B::F::from(1u64));
    let term2 = &one_minus_past * &start_minus_int;

    let sign_input = &term1 + &term2;
    resize_poly(&sign_input, log_size)
}

fn build_past_sign_input_oracle<B: SnarkBackend>(
    past: &TrackedOracle<B>,
    int_ind: &TrackedOracle<B>,
    start_broadcast: &TrackedOracle<B>,
    log_size: usize,
) -> TrackedOracle<B> {
    let int_minus_start = int_ind - start_broadcast;
    let int_minus_start_minus_one = int_minus_start.sub_scalar_oracle(B::F::from(1u64));
    let start_minus_int = start_broadcast - int_ind;

    let term1 = past * &int_minus_start_minus_one;
    let one_minus_past = past
        .mul_scalar_oracle(-B::F::from(1u64))
        .add_scalar_oracle(B::F::from(1u64));
    let term2 = &one_minus_past * &start_minus_int;

    let sign_input = &term1 + &term2;
    resize_oracle(&sign_input, log_size)
}

// ---- Prover / Verifier impls ----

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
        let Some(PayloadStructure::GadgetPayload(payload)) = virtualized_ir.payload_for_node(&id)
        else {
            panic!("SweepFactors: missing gadget payload");
        };
        let payload = payload.clone();

        let char_input = payload
            .get(CHAR_INPUT_LABEL)
            .expect("SweepFactors: missing CHAR_INPUT")
            .clone();
        let str_input = payload
            .get(STR_INPUT_LABEL)
            .expect("SweepFactors: missing STR_INPUT")
            .clone();
        let char_domain = char_input.log_size();

        // int_ind is column 2 of char_input (see rebuild_char_input).
        let int_ind = char_input
            .tracked_col_by_ind(char_input.data_tracked_polys_indices()[2])
            .data_tracked_poly();

        // Initial activators come from the caller-supplied tables.
        let alive_c_0 = char_input
            .activator_tracked_poly()
            .expect("SweepFactors: CHAR_INPUT must carry alive_c_0");
        let alive_h_0 = str_input
            .activator_tracked_poly()
            .expect("SweepFactors: STR_INPUT must carry alive_h_0");

        let t = self.factors.len();
        let mut alive_c: TrackedPoly<B> = alive_c_0;
        let mut alive_h: TrackedPoly<B> = alive_h_0;

        for j in 0..t {
            let (pattern, mode) = &self.factors[j];
            let has_past = j + 1 < t;
            let factor = extract_factor_prover(&payload, j, pattern.len(), *mode, has_past);

            // 1) Rotation chain on this factor's rotated_char columns.
            set_rotation_chain_payload_prover(
                &self.rotation_chains[j],
                &factor.rotated_chars,
                char_domain,
                virtualized_ir,
            );

            // 2) Rebuild inputs with the current alive activators.
            let child_char = rebuild_char_input_prover(&char_input, alive_c.clone());
            let child_str = rebuild_str_input_prover(&str_input, alive_h.clone());

            // 3) Wire FactorPlacement(p_j).
            set_factor_placement_payload_prover(
                &self.factor_placements[j],
                &factor,
                child_char,
                child_str,
                virtualized_ir,
            );

            // 4) Past check (only for j < t - 1) + activator update.
            if let Some(past) = factor.past_col.as_ref() {
                set_bool_past_payload_prover(&self.bool_pasts[j], past, virtualized_ir);
                let sign_input = build_past_sign_input_poly(
                    past,
                    &int_ind,
                    &factor.start_broadcast_col,
                    char_domain,
                );
                set_sign_past_payload_prover(
                    &self.sign_pasts[j],
                    &sign_input,
                    &alive_c,
                    char_domain,
                    virtualized_ir,
                );

                // 5) Alive updates for the next round.
                alive_c = &alive_c * past;
                alive_h = factor.match_col.clone();
            }
        }
        // For the final factor (j = t-1) no past-check is needed and the
        // alive updates from the final round are unused; the caller
        // reads match_{t-1} from the payload.
        let _ = (alive_c, alive_h);
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        // Forward the LIKE-injected plan-time hints down to each
        // per-factor FactorPlacement child. The shared `orig_ind` hint
        // gets fan-out to every child at key
        // `"__like_orig_ind_plan_hint__"`; the per-factor `mark` hint
        // arrives here as `"__like_f{j}_mark_plan_hint__"` and is
        // routed to child `j` under the single-mark key
        // `"__like_mark_plan_hint__"` (each FactorPlacement owns one
        // mark).
        let own = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        let orig_key = "__like_orig_ind_plan_hint__".to_string();
        let orig_ind_hint = match own.get(&orig_key) {
            Some(h) => h.clone(),
            None => return Ok(()),
        };

        for j in 0..self.factors.len() {
            let mark_hint = match own.get(&format!("__like_f{j}_mark_plan_hint__")) {
                Some(h) => h.clone(),
                None => continue,
            };
            let child_id = self.factor_placements[j].id();
            let mut child_payload = match planned_ir.payload_for_node(&child_id) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            child_payload.insert(orig_key.clone(), orig_ind_hint.clone());
            child_payload.insert("__like_mark_plan_hint__".to_string(), mark_hint);
            planned_ir.set_payload_for_node(
                child_id,
                Some(PayloadStructure::GadgetPayload(child_payload)),
            );
        }
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
        let Some(PayloadStructure::GadgetPayload(payload)) = virtualized_ir.payload_for_node(&id)
        else {
            panic!("SweepFactors: missing gadget payload");
        };
        let payload = payload.clone();

        let char_input = payload
            .get(CHAR_INPUT_LABEL)
            .expect("SweepFactors: missing CHAR_INPUT")
            .clone();
        let str_input = payload
            .get(STR_INPUT_LABEL)
            .expect("SweepFactors: missing STR_INPUT")
            .clone();
        let char_domain = char_input.log_size();

        let int_ind = char_input
            .tracked_col_oracle_by_ind(char_input.data_tracked_oracles_indices()[2])
            .data_tracked_oracle();

        let alive_c_0 = char_input
            .activator_tracked_poly()
            .expect("SweepFactors: CHAR_INPUT must carry alive_c_0");
        let alive_h_0 = str_input
            .activator_tracked_poly()
            .expect("SweepFactors: STR_INPUT must carry alive_h_0");

        let t = self.factors.len();
        let mut alive_c: TrackedOracle<B> = alive_c_0;
        let mut alive_h: TrackedOracle<B> = alive_h_0;

        for j in 0..t {
            let (pattern, mode) = &self.factors[j];
            let has_past = j + 1 < t;
            let factor = extract_factor_verifier(&payload, j, pattern.len(), *mode, has_past);

            set_rotation_chain_payload_verifier(
                &self.rotation_chains[j],
                &factor.rotated_chars,
                char_domain,
                virtualized_ir,
            );

            let child_char = rebuild_char_input_verifier(&char_input, alive_c.clone());
            let child_str = rebuild_str_input_verifier(&str_input, alive_h.clone());

            set_factor_placement_payload_verifier(
                &self.factor_placements[j],
                &factor,
                child_char,
                child_str,
                virtualized_ir,
            );

            if let Some(past) = factor.past_col.as_ref() {
                set_bool_past_payload_verifier(&self.bool_pasts[j], past, virtualized_ir);
                let sign_input = build_past_sign_input_oracle(
                    past,
                    &int_ind,
                    &factor.start_broadcast_col,
                    char_domain,
                );
                set_sign_past_payload_verifier(
                    &self.sign_pasts[j],
                    &sign_input,
                    &alive_c,
                    char_domain,
                    virtualized_ir,
                );

                alive_c = &alive_c * past;
                alive_h = factor.match_col.clone();
            }
        }
        let _ = (alive_c, alive_h);
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        // Forward the LIKE-injected plan-time hints down to each
        // per-factor FactorPlacement child. The shared `orig_ind` hint
        // gets fan-out to every child at key
        // `"__like_orig_ind_plan_hint__"`; the per-factor `mark` hint
        // arrives here as `"__like_f{j}_mark_plan_hint__"` and is
        // routed to child `j` under the single-mark key
        // `"__like_mark_plan_hint__"` (each FactorPlacement owns one
        // mark).
        let own = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        let orig_key = "__like_orig_ind_plan_hint__".to_string();
        let orig_ind_hint = match own.get(&orig_key) {
            Some(h) => h.clone(),
            None => return Ok(()),
        };

        for j in 0..self.factors.len() {
            let mark_hint = match own.get(&format!("__like_f{j}_mark_plan_hint__")) {
                Some(h) => h.clone(),
                None => continue,
            };
            let child_id = self.factor_placements[j].id();
            let mut child_payload = match planned_ir.payload_for_node(&child_id) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            child_payload.insert(orig_key.clone(), orig_ind_hint.clone());
            child_payload.insert("__like_mark_plan_hint__".to_string(), mark_hint);
            planned_ir.set_payload_for_node(
                child_id,
                Some(PayloadStructure::GadgetPayload(child_payload)),
            );
        }
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: NodeId,
    ) -> SnarkResult<()> {
        // All constraints are discharged by children (per-factor
        // FactorPlacement, per-factor rotation chain, and per-inter-
        // factor past check). Downstream composites read
        // `MATCH_LABEL_{t-1}` from the payload for their verdict.
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
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        _id: NodeId,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

pub mod witness;

#[cfg(test)]
mod tests;

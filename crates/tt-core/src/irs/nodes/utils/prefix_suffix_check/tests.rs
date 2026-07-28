//! Tests for `PrefixSuffixCheck` composite gadget node (prefix case).
//!
//! Standard fixture (unless a test explicitly diverges):
//! - `n_str = 4` (log_size 2), `n_char = 16` (log_size 4).
//! - String layout:
//!   * String 0: `"abc"`, owns chars 0..=2,   ind = 0, length 3, matches.
//!   * String 1: `"xyz"`, owns chars 3..=5,   ind = 1, length 3, mismatch.
//!   * String 2: `"de"`,  owns chars 6..=7,   ind = 2, length 2, dropped (too short).
//!   * String 3: `"abd"`, owns chars 8..=10,  ind = 3, length 3, mismatch.
//! - Pattern: `"abc"`, k = 3.
//! - Under the prefix filter, only string 0 is kept; strings 1 and 3 are
//!   length-eligible but don't match (two false-negative marks); string 2 is
//!   dropped by the length filter.
//!
//! Having two marks (rather than one) exercises the NoDup gadget on
//! distinct src values, avoiding a degenerate Bezout defrag on a size-1
//! active support.
//!
//! Char literals in this file are encoded as their ASCII byte values.

use std::sync::Arc;

use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{
    CHAR_INPUT_LABEL, Direction, GadgetNode, LENGTH_FILTERED_CHAR_LABEL,
    LENGTH_FILTERED_STR_LABEL, MISMATCH_LABEL, NEW_CHAR_LABEL, NEW_STR_LABEL,
    ROTATED_SELECTORS_LABEL, STR_INPUT_LABEL, SUFFIX_S_B_SHIFTED_LABEL,
};
use crate::irs::nodes::Node;
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const STR_NV: usize = 2; // n_str = 4
const CHAR_NV: usize = 4; // n_char = 16

fn u64_field(name: &str) -> Arc<Field> {
    Arc::new(Field::new(name, DataType::UInt64, false))
}
fn i32_field(name: &str) -> Arc<Field> {
    Arc::new(Field::new(name, DataType::Int32, false))
}
fn bool_field(name: &str) -> Arc<Field> {
    Arc::new(Field::new(name, DataType::Boolean, false))
}

fn u(vs: &[u64]) -> Vec<F> {
    vs.iter().map(|v| F::from(*v)).collect()
}

/// Encodes the fixed pattern `"abc"` as field elements.
fn pattern_abc() -> Vec<F> {
    u(&[b'a' as u64, b'b' as u64, b'c' as u64])
}

/// Standard fixture columns.
///
/// Chars 0..8 hold three strings' text (`abc`, `xyz`, `de`, `abd` — 3+3+2+3=11
/// bytes fill chars 0..=10), and chars 11..=15 are inactive padding.
fn fixture_char_c() -> Vec<F> {
    u(&[
        b'a' as u64, b'b' as u64, b'c' as u64, // string 0: "abc"
        b'x' as u64, b'y' as u64, b'z' as u64, // string 1: "xyz"
        b'd' as u64, b'e' as u64,               // string 2: "de"
        b'a' as u64, b'b' as u64, b'd' as u64, // string 3: "abd"
        0, 0, 0, 0, 0,                          // padding
    ])
}
fn fixture_src() -> Vec<F> {
    u(&[0, 0, 0, 1, 1, 1, 2, 2, 3, 3, 3, 0, 0, 0, 0, 0])
}
fn fixture_s_b() -> Vec<F> {
    // Position 11 is a sentinel "start of string 4" — string 4 doesn't
    // exist, so this bit is inactive under a_c^old, meaning the sentinel
    // never contributes to the prefix anchor (a_c^{old'} · s_b is 0 at
    // position 11). It exists for the SUFFIX direction, where ρ_{−1}(s_b)
    // uses it to place a 1 at position 10 — the last char of string 3.
    // Without the sentinel, the last string of the batch would have no
    // suffix anchor.
    u(&[1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0])
}
/// ρ_{−1}(s_b): the "last char of each string" boundary selector.
fn fixture_s_b_shifted() -> Vec<F> {
    shift_left(&fixture_s_b(), 1)
}
fn fixture_a_c_old() -> Vec<F> {
    u(&[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0])
}
fn fixture_ind() -> Vec<F> {
    u(&[0, 1, 2, 3])
}
fn fixture_l() -> Vec<F> {
    u(&[3, 3, 2, 3])
}
fn fixture_a_h_old() -> Vec<F> {
    u(&[1, 1, 1, 1])
}
/// Length-filter output at k = 3: strings 0, 1, 3 keep; string 2 drops.
fn fixture_a_h_old_prime() -> Vec<F> {
    u(&[1, 1, 0, 1])
}
fn fixture_a_c_old_prime() -> Vec<F> {
    u(&[1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0])
}

/// Compute s'_b^{(i)} := ρ_i(s'_b^{(0)}) (shift right by i).
fn shift_right(xs: &[F], shift: usize) -> Vec<F> {
    let n = xs.len();
    (0..n).map(|i| xs[(i + n - (shift % n)) % n]).collect()
}

/// Build the k-1 rotated selector columns for pattern length k.
fn build_rotated_selectors(anchor: &[F], k: usize) -> Vec<Vec<F>> {
    (1..k).map(|i| shift_right(anchor, i)).collect()
}

/// Compute anchor = a_c^{old'} · s_b.
fn build_anchor(a_c_old_prime: &[F], s_b: &[F]) -> Vec<F> {
    a_c_old_prime.iter().zip(s_b.iter()).map(|(a, b)| *a * *b).collect()
}

/// Shift a vector LEFT by `shift` (result[i] = xs[(i + shift) mod n]).
/// Used to build the suffix-side rotated selectors and the shifted s_b.
fn shift_left(xs: &[F], shift: usize) -> Vec<F> {
    let n = xs.len();
    (0..n).map(|i| xs[(i + (shift % n)) % n]).collect()
}

/// Suffix rotations: s'_a^{(i)} = ρ_{−i}(s'_a^{(0)}) = shift_left(anchor, i).
fn build_rotated_selectors_left(anchor: &[F], k: usize) -> Vec<Vec<F>> {
    (1..k).map(|i| shift_left(anchor, i)).collect()
}

/// Payload assembly.
struct Setup {
    a_h_new: Vec<F>,
    a_c_new: Vec<F>,
    rotated: Vec<Vec<F>>,
    /// Only used when running under Direction::Suffix.
    s_b_shifted: Option<Vec<F>>,
    s_n: Vec<F>,
}

fn honest_setup() -> Setup {
    // Only string 0 matches "abc"; strings 1 and 3 are eligible but don't
    // match (each gets a mismatch witness).
    let a_h_new = u(&[1, 0, 0, 0]);
    let a_c_new = u(&[1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let anchor = build_anchor(&fixture_a_c_old_prime(), &fixture_s_b());
    let rotated = build_rotated_selectors(&anchor, 3);
    // Mark char 3 for string 1 (first slot of "xyz" — 'x' ≠ 'a').
    // For string 3 ("abd"), 'a' matches 'a' at char 8 and 'b' matches 'b'
    // at char 9 — the mismatch is at char 10 ('d' ≠ 'c').
    let s_n = u(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let mut s_n = s_n;
    s_n[10] = F::from(1u64);
    Setup {
        a_h_new,
        a_c_new,
        rotated,
        s_b_shifted: None,
        s_n,
    }
}

fn run(setup: Setup) -> Result<(), ark_piop::errors::SnarkError> {
    run_with_direction(Direction::Prefix, setup)
}

/// Honest setup for `LIKE '%abc'` on the same fixture. Only string 0
/// (`"abc"`) actually ends with `"abc"`; strings 1 (`"xyz"`) and 3
/// (`"abd"`) are eligible but don't end with `"abc"`.
fn honest_suffix_setup() -> Setup {
    let a_h_new = u(&[1, 0, 0, 0]);
    // a_c^new activates string 0's char slots (0..=2). Under the suffix
    // filter, the "kept" chars are exactly those of a matched string.
    let a_c_new = u(&[1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    // Anchor for suffix: a_c^{old'} · ρ_{−1}(s_b), then rotate LEFT (Direction::Left).
    let s_b_shifted = fixture_s_b_shifted();
    let anchor: Vec<F> = fixture_a_c_old_prime()
        .iter()
        .zip(s_b_shifted.iter())
        .map(|(a, b)| *a * *b)
        .collect();
    let rotated = build_rotated_selectors_left(&anchor, 3);

    // Under suffix indexing (π(i) = k−1−i), the pattern column p is
    //   'c'·s'_a^{(0)} + 'b'·s'_a^{(1)} + 'a'·s'_a^{(2)}.
    // For string 1 ("xyz"), all three anchored slots (5, 4, 3) mismatch p
    // — pick position 3 as the witness (c='x', p='a').
    // For string 3 ("abd"), anchor slots are (10, 9, 8) → 'd' vs 'c',
    // 'b' vs 'b', 'a' vs 'a'; only position 10 mismatches. Mark it.
    let mut s_n = u(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    s_n[10] = F::from(1u64);

    Setup {
        a_h_new,
        a_c_new,
        rotated,
        s_b_shifted: Some(s_b_shifted),
        s_n,
    }
}

fn run_suffix(setup: Setup) -> Result<(), ark_piop::errors::SnarkError> {
    run_with_direction(Direction::Suffix, setup)
}

fn run_with_direction(
    direction: Direction,
    setup: Setup,
) -> Result<(), ark_piop::errors::SnarkError> {
    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(
        pattern_abc(),
        direction,
    ))));
    let gadget_id = gadget.id();

    let c_f = u64_field("c");
    let src_f = u64_field("src");
    let s_b_f = u64_field("s_b");
    let ind_f = u64_field("ind");
    let l_f = i32_field("l");
    let flag = bool_field("data");

    let char_input_schema = Schema::new(vec![
        c_f.as_ref().clone(),
        src_f.as_ref().clone(),
        s_b_f.as_ref().clone(),
    ]);
    let str_input_schema = Schema::new(vec![ind_f.as_ref().clone(), l_f.as_ref().clone()]);
    let lf_char_schema = Schema::new(vec![flag.as_ref().clone()]);
    let lf_str_schema = Schema::new(vec![flag.as_ref().clone()]);
    let new_char_schema = Schema::new(vec![flag.as_ref().clone()]);
    let new_str_schema = Schema::new(vec![flag.as_ref().clone()]);
    let rot_schema = Schema::new(
        (1..pattern_abc().len())
            .map(|i| Field::new(format!("s_b_prime_{i}"), DataType::UInt64, false))
            .collect::<Vec<_>>(),
    );
    let mis_schema = Schema::new(vec![flag.as_ref().clone()]);

    // Rotated selectors: k-1 columns.
    let rot_cols: Vec<(Arc<Field>, Vec<F>)> = setup
        .rotated
        .into_iter()
        .enumerate()
        .map(|(i, v)| (Arc::new(Field::new(format!("s_b_prime_{}", i + 1), DataType::UInt64, false)), v))
        .collect();

    // SRS log_size 16 covers the sign gadget's 2^16 range polynomial from
    // LengthFilteringCheck's Int32 chunks.
    let harness = GadgetHarness::<B>::builder(16)
        .with_gadget(gadget)
        .with_table(
            gadget_id,
            CHAR_INPUT_LABEL,
            TableSpec {
                schema: char_input_schema,
                log_size: CHAR_NV,
                cols: vec![
                    (c_f, fixture_char_c()),
                    (src_f, fixture_src()),
                    (s_b_f, fixture_s_b()),
                ],
                activator: Some(fixture_a_c_old()),
            },
        )
        .with_table(
            gadget_id,
            STR_INPUT_LABEL,
            TableSpec {
                schema: str_input_schema,
                log_size: STR_NV,
                cols: vec![(ind_f, fixture_ind()), (l_f, fixture_l())],
                activator: Some(fixture_a_h_old()),
            },
        )
        .with_table(
            gadget_id,
            LENGTH_FILTERED_CHAR_LABEL,
            TableSpec {
                schema: lf_char_schema,
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), fixture_a_c_old_prime())],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            LENGTH_FILTERED_STR_LABEL,
            TableSpec {
                schema: lf_str_schema,
                log_size: STR_NV,
                cols: vec![(flag.clone(), fixture_a_h_old_prime())],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            NEW_CHAR_LABEL,
            TableSpec {
                schema: new_char_schema,
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), setup.a_c_new)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            NEW_STR_LABEL,
            TableSpec {
                schema: new_str_schema,
                log_size: STR_NV,
                cols: vec![(flag.clone(), setup.a_h_new)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            ROTATED_SELECTORS_LABEL,
            TableSpec {
                schema: rot_schema,
                log_size: CHAR_NV,
                cols: rot_cols,
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            MISMATCH_LABEL,
            TableSpec {
                schema: mis_schema,
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), setup.s_n)],
                activator: None,
            },
        );

    let harness = if let Some(shifted) = setup.s_b_shifted {
        let shifted_f = u64_field("s_b_shifted");
        let shifted_schema = Schema::new(vec![shifted_f.as_ref().clone()]);
        harness.with_table(
            gadget_id,
            SUFFIX_S_B_SHIFTED_LABEL,
            TableSpec {
                schema: shifted_schema,
                log_size: CHAR_NV,
                cols: vec![(shifted_f, shifted)],
                activator: None,
            },
        )
    } else {
        harness
    };

    let harness = harness.build();
    run_gadget_pipeline(harness)
}

// ---- Positive ----

#[test]
fn honest_prefix_matches_and_mismatches_verify() {
    run(honest_setup()).expect("honest prefix check should verify");
}

// ---- Adversarial ----

#[test]
fn non_boolean_a_h_new_rejected() {
    let mut s = honest_setup();
    s.a_h_new[0] = F::from(2u64);
    assert!(run(s).is_err(), "non-boolean a_h^new must be rejected by BoolCheck");
}

#[test]
fn keeping_non_matching_string_rejected_by_false_positive() {
    let mut s = honest_setup();
    // Claim string 1 also matches, even though "xyz" != "abc".
    s.a_h_new = u(&[1, 1, 0, 0]);
    s.a_c_new = u(&[1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert!(
        run(s).is_err(),
        "keeping a non-matching string must be rejected by the false-positive zerocheck"
    );
}

#[test]
fn dropping_matching_string_rejected_by_false_negative_no_marker() {
    let mut s = honest_setup();
    // Claim string 0 doesn't match, and give no mismatch marker for it.
    s.a_h_new = u(&[0, 0, 0, 0]);
    s.a_c_new = u(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    // Only marker for string 1 as before; string 0 is dropped with no marker.
    // n_m = 0, n_nm = 1, but |eligible| = 2, so the third sumcheck (a_h^{old'} sum)
    // will disagree.
    assert!(
        run(s).is_err(),
        "silently dropping a matching string must be rejected by the count sumchecks"
    );
}

#[test]
fn wrong_mark_on_matching_string_rejected_by_nozero() {
    let mut s = honest_setup();
    // Prover marks a slot on string 0 as a mismatch, but c[0] = p[0] = 'a'
    // there, so `s_n · (c - p) + (1 - s_n)` collapses to 0.
    s.s_n = u(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert!(
        run(s).is_err(),
        "marking a matching position as mismatch must be rejected by NoZeroCheck"
    );
}

// NOTE: the "duplicate marks on the same string" adversarial case is
// deliberately omitted here — this cut of the gadget does not wire up the
// NoDup child on (src, s_n). Once NoDup is enabled, add a test that marks
// two anchored slots of the same string and asserts rejection.

#[test]
fn mark_on_non_anchored_slot_rejected_by_confinement() {
    let mut s = honest_setup();
    // Char 6 belongs to string 2 (dropped by length filter). Its S = 0, so
    // a mark there triggers the confinement zerocheck s_n · (1 - S) = 0.
    s.s_n = u(&[0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert!(
        run(s).is_err(),
        "marking a non-anchored slot must be rejected by the confinement zerocheck"
    );
}

#[test]
fn tampered_rotated_selector_rejected_by_rotation_check() {
    let mut s = honest_setup();
    // Corrupt one entry of s'_b^{(1)} so it no longer matches ρ_1(anchor).
    s.rotated[0][0] = F::from(1u64);
    assert!(
        run(s).is_err(),
        "tampered rotation must be rejected by RotationCheck"
    );
}

// ==== Suffix direction ====

#[test]
fn honest_suffix_matches_and_mismatches_verify() {
    run_suffix(honest_suffix_setup()).expect("honest suffix check should verify");
}

#[test]
fn suffix_keeping_non_matching_string_rejected_by_false_positive() {
    let mut s = honest_suffix_setup();
    // Claim string 1 also matches (`"xyz"` supposedly ends with `"abc"`).
    s.a_h_new = u(&[1, 1, 0, 0]);
    s.a_c_new = u(&[1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert!(
        run_suffix(s).is_err(),
        "keeping a non-matching string under suffix must be rejected"
    );
}

#[test]
fn suffix_tampered_s_b_shifted_rejected_by_rotation_check() {
    let mut s = honest_suffix_setup();
    // Corrupt s_b_shifted so the extra RotationCheck (s_b_shifted =
    // ρ_{−1}(s_b)) fails.
    let mut shifted = s.s_b_shifted.unwrap();
    shifted[0] = F::from(1u64);
    s.s_b_shifted = Some(shifted);
    assert!(
        run_suffix(s).is_err(),
        "tampered s_b_shifted must be rejected by the extra suffix RotationCheck"
    );
}

#[test]
fn suffix_wrong_mark_on_matching_string_rejected_by_nozero() {
    let mut s = honest_suffix_setup();
    // String 0 matches. Marking any of its anchored slots (0, 1, 2) as a
    // mismatch would trip the NoZeroCheck (c = p at that position).
    s.s_n = u(&[0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert!(
        run_suffix(s).is_err(),
        "marking a matching position under suffix must be rejected by NoZeroCheck"
    );
}

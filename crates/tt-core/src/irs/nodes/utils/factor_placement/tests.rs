//! Tests for `FactorPlacement` (paper PIOP 8, prefix mode).
//!
//! Standard fixture:
//! - n_str = 2, n_char = 4.
//! - Two strings, both length 2, laid out contiguously:
//!   * String 0: `"ab"`, chars 0..=1, ind = 0.
//!   * String 1: `"ab"`, chars 2..=3, ind = 1.
//! - Pattern factor: `"ab"` (ℓ = 2), Mode::Prefix.
//! - Both strings match, so we get two marks — comfortably above the
//!   Bezout NoDup size-1 defrag degeneracy.

use std::sync::Arc;

use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{
    ATT_MASK_LABEL, CHAR_INPUT_LABEL, GadgetNode, MARK_LABEL, MATCH_BROADCAST_LABEL,
    MATCH_LABEL, Mode, OCCURS_LABEL, ROTATED_BND_LABEL, ROTATED_CHAR_LABEL, START_LABEL,
    STR_INPUT_LABEL,
};
use crate::irs::nodes::Node;
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const STR_NV: usize = 2; // n_str = 4 (2 real strings + 2 inactive)
const CHAR_NV: usize = 2; // n_char = 4

fn u(vs: &[u64]) -> Vec<F> {
    vs.iter().map(|v| F::from(*v)).collect()
}
fn u64_field(name: &str) -> Arc<Field> {
    Arc::new(Field::new(name, DataType::UInt64, false))
}
fn bool_field(name: &str) -> Arc<Field> {
    Arc::new(Field::new(name, DataType::Boolean, false))
}

/// Shift LEFT by δ: result[i] = xs[(i + δ) mod n]. (This is what
/// `char^(δ)[c] = char[c + δ]` means at the char level.)
fn shift_left(xs: &[F], shift: usize) -> Vec<F> {
    let n = xs.len();
    (0..n).map(|i| xs[(i + (shift % n)) % n]).collect()
}

fn fixture_char() -> Vec<F> {
    u(&[b'a' as u64, b'b' as u64, b'a' as u64, b'b' as u64])
}
fn fixture_orig_ind() -> Vec<F> {
    u(&[0, 0, 1, 1])
}
fn fixture_int_ind() -> Vec<F> {
    u(&[0, 1, 0, 1])
}
fn fixture_bnd() -> Vec<F> {
    u(&[1, 0, 1, 0])
}
fn fixture_char_act() -> Vec<F> {
    u(&[1, 1, 1, 1])
}
fn fixture_ind() -> Vec<F> {
    u(&[0, 1, 2, 3])
}
fn fixture_a() -> Vec<F> {
    u(&[1, 1, 0, 0])
}

fn pattern_ab() -> Vec<F> {
    u(&[b'a' as u64, b'b' as u64])
}

/// Build the honest witness columns: rotated_chars, occurs, match,
/// match_broadcast, mark, start.
struct Witness {
    rotated: Vec<Vec<F>>,
    occurs: Vec<F>,
    match_str: Vec<F>,
    match_broadcast: Vec<F>,
    mark: Vec<F>,
    start: Vec<F>,
}

fn honest_witness() -> Witness {
    let char = fixture_char();
    // char^(0) = char, char^(1) = shift_left(char, 1).
    let rotated = vec![char.clone(), shift_left(&char, 1)];
    // Occurrences of "ab" at char positions 0 and 2.
    let occurs = u(&[1, 0, 1, 0]);
    // Both real strings match; padding strings are inactive.
    let match_str = u(&[1, 1, 0, 0]);
    // Broadcast to char level: match_broadcast[c] = match[orig_ind[c]].
    let match_broadcast = u(&[1, 1, 1, 1]);
    // Only the (leftmost — trivially, only) occurrence of each string is marked.
    let mark = u(&[1, 0, 1, 0]);
    let start = u(&[0, 0, 0, 0]);
    Witness {
        rotated,
        occurs,
        match_str,
        match_broadcast,
        mark,
        start,
    }
}

fn run(witness: Witness) -> Result<(), ark_piop::errors::SnarkError> {
    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(
        pattern_ab(),
        Mode::Prefix,
    ))));
    let gadget_id = gadget.id();

    let char_f = u64_field("char");
    let orig_ind_f = u64_field("orig_ind");
    let int_ind_f = u64_field("int_ind");
    let bnd_f = u64_field("bnd");
    let ind_f = u64_field("ind");
    let flag = bool_field("data");

    let char_input_schema = Schema::new(vec![
        char_f.as_ref().clone(),
        orig_ind_f.as_ref().clone(),
        int_ind_f.as_ref().clone(),
        bnd_f.as_ref().clone(),
    ]);
    let str_input_schema = Schema::new(vec![ind_f.as_ref().clone()]);
    let rot_schema = Schema::new(
        (0..pattern_ab().len())
            .map(|d| Field::new(format!("char_{d}"), DataType::UInt64, false))
            .collect::<Vec<_>>(),
    );
    let flag_schema = Schema::new(vec![flag.as_ref().clone()]);

    let rot_cols: Vec<(Arc<Field>, Vec<F>)> = witness
        .rotated
        .into_iter()
        .enumerate()
        .map(|(d, v)| {
            (
                Arc::new(Field::new(format!("char_{d}"), DataType::UInt64, false)),
                v,
            )
        })
        .collect();

    let match_prime_f = u64_field("match_prime");

    let harness = GadgetHarness::<B>::builder(8)
        .with_gadget(gadget)
        .with_table(
            gadget_id,
            CHAR_INPUT_LABEL,
            TableSpec {
                schema: char_input_schema,
                log_size: CHAR_NV,
                cols: vec![
                    (char_f, fixture_char()),
                    (orig_ind_f, fixture_orig_ind()),
                    (int_ind_f, fixture_int_ind()),
                    (bnd_f, fixture_bnd()),
                ],
                activator: Some(fixture_char_act()),
            },
        )
        .with_table(
            gadget_id,
            STR_INPUT_LABEL,
            TableSpec {
                schema: str_input_schema,
                log_size: STR_NV,
                cols: vec![(ind_f, fixture_ind())],
                activator: Some(fixture_a()),
            },
        )
        .with_table(
            gadget_id,
            ROTATED_CHAR_LABEL,
            TableSpec {
                schema: rot_schema,
                log_size: CHAR_NV,
                cols: rot_cols,
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            OCCURS_LABEL,
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), witness.occurs)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            MATCH_LABEL,
            TableSpec {
                schema: flag_schema.clone(),
                log_size: STR_NV,
                cols: vec![(flag.clone(), witness.match_str)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            MARK_LABEL,
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), witness.mark)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            START_LABEL,
            TableSpec {
                schema: Schema::new(vec![Field::new("start", DataType::UInt64, false)]),
                log_size: STR_NV,
                cols: vec![(u64_field("start"), witness.start)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            MATCH_BROADCAST_LABEL,
            TableSpec {
                schema: Schema::new(vec![match_prime_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(match_prime_f, witness.match_broadcast)],
                activator: None,
            },
        )
        .build();

    run_gadget_pipeline(harness)
}

#[test]
fn honest_prefix_match_verifies() {
    run(honest_witness()).expect("honest prefix Factor Placement should verify");
}

/// Honest suffix Factor Placement.
///
/// Fixture chosen so that prefix and suffix att_mask differ (unlike the
/// prefix fixture where both would coincide):
/// - n_str = 8, n_char = 8 (matched log sizes = 3).
/// - Two real strings, both `"abab"` of length 4, packed contiguously in
///   char positions 0..=7; six inactive padding strings.
/// - Pattern factor: `"ab"` (ℓ = 2), Mode::Suffix.
/// - Both strings' suffix `"ab"` matches; the valid suffix windows sit at
///   char positions 2 (for string 0) and 6 (for string 1) — different from
///   the prefix windows at 0 and 4.
#[test]
fn honest_suffix_match_verifies() {
    const STR_NV: usize = 3; // n_str = 8
    const CHAR_NV: usize = 3; // n_char = 8

    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(
        pattern_ab(),
        Mode::Suffix,
    ))));
    let gadget_id = gadget.id();

    // char = "abab" + "abab", both strings packed contiguously.
    let char_col = u(&[
        b'a' as u64, b'b' as u64, b'a' as u64, b'b' as u64,
        b'a' as u64, b'b' as u64, b'a' as u64, b'b' as u64,
    ]);
    let orig_ind = u(&[0, 0, 0, 0, 1, 1, 1, 1]);
    let int_ind = u(&[0, 1, 2, 3, 0, 1, 2, 3]);
    let bnd = u(&[1, 0, 0, 0, 1, 0, 0, 0]);
    let char_act = u(&[1; 8]);
    let ind = u(&[0, 1, 2, 3, 4, 5, 6, 7]);
    let a = u(&[1, 1, 0, 0, 0, 0, 0, 0]);

    // char^(0) = char, char^(1) = shift_left(char, 1).
    let rotated = vec![char_col.clone(), shift_left(&char_col, 1)];

    // att_mask = ρ_{-2}(char_act · bnd) = [0, 0, 1, 0, 0, 0, 1, 0].
    // (char_act · bnd = [1, 0, 0, 0, 1, 0, 0, 0]; shift left by 2.)
    let att_mask = u(&[0, 0, 1, 0, 0, 0, 1, 0]);

    // Only the two valid suffix windows have both att_mask=1 AND matching
    // fingerprint; that's exactly where occurs is 1.
    let occurs = u(&[0, 0, 1, 0, 0, 0, 1, 0]);
    let match_str = u(&[1, 1, 0, 0, 0, 0, 0, 0]);
    let match_broadcast = u(&[1, 1, 1, 1, 1, 1, 1, 1]);
    let mark = u(&[0, 0, 1, 0, 0, 0, 1, 0]);
    // string 0's suffix window starts at char 2; string 1's at char 6.
    let start = u(&[2, 6, 0, 0, 0, 0, 0, 0]);

    let char_f = u64_field("char");
    let orig_ind_f = u64_field("orig_ind");
    let int_ind_f = u64_field("int_ind");
    let bnd_f = u64_field("bnd");
    let ind_f = u64_field("ind");
    let flag = bool_field("data");
    let att_mask_f = u64_field("att_mask");

    let char_input_schema = Schema::new(vec![
        char_f.as_ref().clone(),
        orig_ind_f.as_ref().clone(),
        int_ind_f.as_ref().clone(),
        bnd_f.as_ref().clone(),
    ]);
    let str_input_schema = Schema::new(vec![ind_f.as_ref().clone()]);
    let rot_schema = Schema::new(
        (0..pattern_ab().len())
            .map(|d| Field::new(format!("char_{d}"), DataType::UInt64, false))
            .collect::<Vec<_>>(),
    );
    let flag_schema = Schema::new(vec![flag.as_ref().clone()]);

    let rot_cols: Vec<(Arc<Field>, Vec<F>)> = rotated
        .into_iter()
        .enumerate()
        .map(|(d, v)| {
            (
                Arc::new(Field::new(format!("char_{d}"), DataType::UInt64, false)),
                v,
            )
        })
        .collect();

    let match_prime_f = u64_field("match_prime");

    let harness = GadgetHarness::<B>::builder(8)
        .with_gadget(gadget)
        .with_table(
            gadget_id,
            CHAR_INPUT_LABEL,
            TableSpec {
                schema: char_input_schema,
                log_size: CHAR_NV,
                cols: vec![
                    (char_f, char_col),
                    (orig_ind_f, orig_ind),
                    (int_ind_f, int_ind),
                    (bnd_f, bnd),
                ],
                activator: Some(char_act),
            },
        )
        .with_table(
            gadget_id,
            STR_INPUT_LABEL,
            TableSpec {
                schema: str_input_schema,
                log_size: STR_NV,
                cols: vec![(ind_f, ind)],
                activator: Some(a),
            },
        )
        .with_table(
            gadget_id,
            ROTATED_CHAR_LABEL,
            TableSpec {
                schema: rot_schema,
                log_size: CHAR_NV,
                cols: rot_cols,
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            OCCURS_LABEL,
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), occurs)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            MATCH_LABEL,
            TableSpec {
                schema: flag_schema.clone(),
                log_size: STR_NV,
                cols: vec![(flag.clone(), match_str)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            MARK_LABEL,
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), mark)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            START_LABEL,
            TableSpec {
                schema: Schema::new(vec![Field::new("start", DataType::UInt64, false)]),
                log_size: STR_NV,
                cols: vec![(u64_field("start"), start)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            MATCH_BROADCAST_LABEL,
            TableSpec {
                schema: Schema::new(vec![match_prime_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(match_prime_f, match_broadcast)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            ATT_MASK_LABEL,
            TableSpec {
                schema: Schema::new(vec![att_mask_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(att_mask_f, att_mask)],
                activator: None,
            },
        )
        .build();

    run_gadget_pipeline(harness).expect("honest suffix Factor Placement should verify");
}

/// Honest infix Factor Placement.
///
/// Fixture:
/// - n_str = 8, n_char = 8 (matched log sizes = 3).
/// - Two real strings: `"cab"` (chars 0..=2) and `"abc"` (chars 3..=5);
///   char slots 6..=7 are padding (char-act = 0), string slots 2..=7 are
///   padding (a = 0).
/// - Pattern factor: `"ab"` (ℓ = 2), Mode::Infix.
/// - Both strings contain `"ab"` as a factor: string 0 at char pos 1,
///   string 1 at char pos 3. Two marks (≥ 2, avoiding the size-1 Bezout
///   NoDup degeneracy).
///
/// Sanity-checks the infix-specific machinery: the `ROTATED_BND_LABEL`
/// payload (bnd(1)), the single RotationCheck child on `(bnd, bnd(1), -1)`,
/// and the `att_mask := char-act · (1 - bnd(1))` derivation. The prefix
/// mode would have produced att_mask `[1,0,0,1,0,0,0,0]` — very different
/// from the infix `[1,1,0,1,1,0,0,0]` used here.
#[test]
fn honest_infix_match_verifies() {
    const STR_NV: usize = 3; // n_str = 8
    const CHAR_NV: usize = 3; // n_char = 8

    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(
        pattern_ab(),
        Mode::Infix,
    ))));
    let gadget_id = gadget.id();

    // "cab" + "abc" + padding.
    let char_col = u(&[
        b'c' as u64, b'a' as u64, b'b' as u64,
        b'a' as u64, b'b' as u64, b'c' as u64,
        0, 0,
    ]);
    let orig_ind = u(&[0, 0, 0, 1, 1, 1, 0, 0]);
    let int_ind = u(&[0, 1, 2, 0, 1, 2, 0, 0]);
    // Sentinel bit at position 6 marks "start after string 1 ends", so the
    // last-char position of string 1 (char 5) is correctly disallowed as an
    // infix-window start.
    let bnd = u(&[1, 0, 0, 1, 0, 0, 1, 0]);
    let char_act = u(&[1, 1, 1, 1, 1, 1, 0, 0]);
    let ind = u(&[0, 1, 2, 3, 4, 5, 6, 7]);
    let a = u(&[1, 1, 0, 0, 0, 0, 0, 0]);

    // char(0) = char, char(1) = shift_left(char, 1).
    let rotated_chars = vec![char_col.clone(), shift_left(&char_col, 1)];
    // bnd(1)[c] = bnd[(c+1) mod 8].
    let bnd_1 = shift_left(&bnd, 1);
    // Ensure the fixture matches what the RotationCheck will verify.
    assert_eq!(bnd_1, u(&[0, 0, 1, 0, 0, 1, 0, 1]));

    // Occurs and mark: valid infix window at c=1 (chars 1..2 = "ab") and
    // c=3 (chars 3..4 = "ab"); at c=2 and c=5 att_mask=0 blocks; at c=4
    // fingerprint mismatches ("bc" ≠ "ab").
    let occurs = u(&[0, 1, 0, 1, 0, 0, 0, 0]);
    let match_str = u(&[1, 1, 0, 0, 0, 0, 0, 0]);
    let match_broadcast = u(&[1, 1, 1, 1, 1, 1, 1, 1]);
    let mark = u(&[0, 1, 0, 1, 0, 0, 0, 0]);
    // String 0's match starts at c=1; string 1's at c=3.
    let start = u(&[1, 3, 0, 0, 0, 0, 0, 0]);

    let char_f = u64_field("char");
    let orig_ind_f = u64_field("orig_ind");
    let int_ind_f = u64_field("int_ind");
    let bnd_f = u64_field("bnd");
    let ind_f = u64_field("ind");
    let flag = bool_field("data");
    let bnd_1_f = u64_field("bnd_1");

    let char_input_schema = Schema::new(vec![
        char_f.as_ref().clone(),
        orig_ind_f.as_ref().clone(),
        int_ind_f.as_ref().clone(),
        bnd_f.as_ref().clone(),
    ]);
    let str_input_schema = Schema::new(vec![ind_f.as_ref().clone()]);
    let rot_char_schema = Schema::new(
        (0..pattern_ab().len())
            .map(|d| Field::new(format!("char_{d}"), DataType::UInt64, false))
            .collect::<Vec<_>>(),
    );
    let flag_schema = Schema::new(vec![flag.as_ref().clone()]);

    let rot_char_cols: Vec<(Arc<Field>, Vec<F>)> = rotated_chars
        .into_iter()
        .enumerate()
        .map(|(d, v)| {
            (
                Arc::new(Field::new(format!("char_{d}"), DataType::UInt64, false)),
                v,
            )
        })
        .collect();

    let match_prime_f = u64_field("match_prime");

    let harness = GadgetHarness::<B>::builder(8)
        .with_gadget(gadget)
        .with_table(
            gadget_id,
            CHAR_INPUT_LABEL,
            TableSpec {
                schema: char_input_schema,
                log_size: CHAR_NV,
                cols: vec![
                    (char_f, char_col),
                    (orig_ind_f, orig_ind),
                    (int_ind_f, int_ind),
                    (bnd_f, bnd),
                ],
                activator: Some(char_act),
            },
        )
        .with_table(
            gadget_id,
            STR_INPUT_LABEL,
            TableSpec {
                schema: str_input_schema,
                log_size: STR_NV,
                cols: vec![(ind_f, ind)],
                activator: Some(a),
            },
        )
        .with_table(
            gadget_id,
            ROTATED_CHAR_LABEL,
            TableSpec {
                schema: rot_char_schema,
                log_size: CHAR_NV,
                cols: rot_char_cols,
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            OCCURS_LABEL,
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), occurs)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            MATCH_LABEL,
            TableSpec {
                schema: flag_schema.clone(),
                log_size: STR_NV,
                cols: vec![(flag.clone(), match_str)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            MARK_LABEL,
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), mark)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            START_LABEL,
            TableSpec {
                schema: Schema::new(vec![Field::new("start", DataType::UInt64, false)]),
                log_size: STR_NV,
                cols: vec![(u64_field("start"), start)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            MATCH_BROADCAST_LABEL,
            TableSpec {
                schema: Schema::new(vec![match_prime_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(match_prime_f, match_broadcast)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            ROTATED_BND_LABEL,
            TableSpec {
                schema: Schema::new(vec![bnd_1_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(bnd_1_f, bnd_1)],
                activator: None,
            },
        )
        .build();

    run_gadget_pipeline(harness).expect("honest infix Factor Placement should verify");
}

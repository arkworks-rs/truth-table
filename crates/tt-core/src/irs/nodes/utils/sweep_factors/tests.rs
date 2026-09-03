//! End-to-end tests for SweepFactors (paper §6.1 PIOP 7).
//!
//! - `honest_t1_prefix_verifies` — smoke test that the t=1 special case
//!   behaves as expected (equivalent scope to FactorPlacement's own
//!   prefix test, but routed through SweepFactors).
//! - `honest_t2_two_infix_verifies` — realistic multi-factor case:
//!   pattern `%ab%cd%` (two infix factors) against `"abcd"`. Exercises
//!   the past_j chain, activator threading, and per-factor rotation
//!   verification.

use std::sync::Arc;

use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{
    CHAR_INPUT_LABEL, GadgetNode, Mode, STR_INPUT_LABEL, factor_label,
    parse_like_pattern,
};
use crate::irs::nodes::Node;
use crate::irs::nodes::utils::nodup;
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

fn u(vs: &[u64]) -> Vec<F> {
    vs.iter().map(|v| F::from(*v)).collect()
}
fn u64_field(name: &str) -> Arc<Field> {
    Arc::new(Field::new(name, DataType::UInt64, false))
}
fn bool_field(name: &str) -> Arc<Field> {
    Arc::new(Field::new(name, DataType::Boolean, false))
}
fn shift_left(xs: &[F], shift: usize) -> Vec<F> {
    let n = xs.len();
    (0..n).map(|i| xs[(i + (shift % n)) % n]).collect()
}

fn pattern(bytes: &[u8]) -> Vec<F> {
    bytes.iter().map(|b| F::from(*b as u64)).collect()
}

// -----------------------------------------------------------------------------
// t = 1: single-factor prefix
// -----------------------------------------------------------------------------

#[test]
fn honest_t1_prefix_verifies() {
    const STR_NV: usize = 2;
    const CHAR_NV: usize = 2;

    let factors = vec![(pattern(b"ab"), Mode::Prefix)];
    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new_with_nodup_mode(
        factors,
        nodup::Mode::BezoutBased,
    ))));
    let gadget_id = gadget.id();

    // Same "ab" + "ab" fixture as the FactorPlacement prefix test.
    let char_col = u(&[b'a' as u64, b'b' as u64, b'a' as u64, b'b' as u64]);
    let orig_ind = u(&[0, 0, 1, 1]);
    let int_ind = u(&[0, 1, 0, 1]);
    let bnd = u(&[1, 0, 1, 0]);
    let char_act = u(&[1, 1, 1, 1]);
    let ind = u(&[0, 1, 2, 3]);
    let a = u(&[1, 1, 0, 0]);

    let rotated = vec![char_col.clone(), shift_left(&char_col, 1)];

    let occurs = u(&[1, 0, 1, 0]);
    let match_str = u(&[1, 1, 0, 0]);
    let mark = u(&[1, 0, 1, 0]);
    let start = u(&[0, 0, 0, 0]);
    let match_broadcast = u(&[1, 1, 1, 1]);
    let start_broadcast = u(&[0, 0, 0, 0]);
    let leftmost_mask = u(&[0, 0, 0, 0]);

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
    let flag_schema = Schema::new(vec![flag.as_ref().clone()]);
    let rot_schema = Schema::new(
        (0..2)
            .map(|d| Field::new(format!("char_{d}"), DataType::UInt64, false))
            .collect::<Vec<_>>(),
    );

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
    let start_bcast_f = u64_field("start_broadcast");
    let mask_f = u64_field("leftmost_mask");
    let start_f = u64_field("start");

    let harness = GadgetHarness::<B>::builder(16)
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
            &factor_label(0, "rotated_char"),
            TableSpec {
                schema: rot_schema,
                log_size: CHAR_NV,
                cols: rot_cols,
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "occurs"),
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), occurs)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "match"),
            TableSpec {
                schema: flag_schema.clone(),
                log_size: STR_NV,
                cols: vec![(flag.clone(), match_str)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "mark"),
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), mark)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "start"),
            TableSpec {
                schema: Schema::new(vec![start_f.as_ref().clone()]),
                log_size: STR_NV,
                cols: vec![(start_f, start)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "match_broadcast"),
            TableSpec {
                schema: Schema::new(vec![match_prime_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(match_prime_f, match_broadcast)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "start_broadcast"),
            TableSpec {
                schema: Schema::new(vec![start_bcast_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(start_bcast_f, start_broadcast)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "leftmost_mask"),
            TableSpec {
                schema: Schema::new(vec![mask_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(mask_f, leftmost_mask)],
                activator: None,
            },
        )
        .build();

    run_gadget_pipeline(harness).expect("SweepFactors t=1 prefix should verify");
}

// -----------------------------------------------------------------------------
// t = 2: two infix factors — `%ab%cd%` against "abcd" | "abcd"
// -----------------------------------------------------------------------------

#[test]
fn honest_t2_two_infix_verifies() {
    const STR_NV: usize = 3; // 8 slots (2 real strings + 6 pad, though we use 2)
    const CHAR_NV: usize = 3; // 8 slots

    let factors = vec![
        (pattern(b"ab"), Mode::Infix),
        (pattern(b"cd"), Mode::Infix),
    ];
    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new_with_nodup_mode(
        factors,
        nodup::Mode::BezoutBased,
    ))));
    let gadget_id = gadget.id();

    // Two strings "abcd" and "abcd", packed contiguously.
    let char_col = u(&[
        b'a' as u64, b'b' as u64, b'c' as u64, b'd' as u64,
        b'a' as u64, b'b' as u64, b'c' as u64, b'd' as u64,
    ]);
    let orig_ind = u(&[0, 0, 0, 0, 1, 1, 1, 1]);
    let int_ind = u(&[0, 1, 2, 3, 0, 1, 2, 3]);
    let bnd = u(&[1, 0, 0, 0, 1, 0, 0, 0]);
    let char_act = u(&[1, 1, 1, 1, 1, 1, 1, 1]);
    let ind = u(&[0, 1, 2, 3, 4, 5, 6, 7]);
    let a = u(&[1, 1, 0, 0, 0, 0, 0, 0]);

    // Rotated char columns for each factor (both ℓ = 2).
    let char_0 = char_col.clone();
    let char_1 = shift_left(&char_col, 1);

    // bnd(1) = shift_left(bnd, 1) — used by both infix rotated_bnd tables.
    let bnd_1 = shift_left(&bnd, 1);

    // ---- Factor 0: "ab" ----
    let occurs_0 = u(&[1, 0, 0, 0, 1, 0, 0, 0]);
    let match_str_0 = u(&[1, 1, 0, 0, 0, 0, 0, 0]);
    let mark_0 = u(&[1, 0, 0, 0, 1, 0, 0, 0]);
    let start_0 = u(&[0, 0, 0, 0, 0, 0, 0, 0]);
    let match_broadcast_0 = u(&[1, 1, 1, 1, 1, 1, 1, 1]);
    let start_broadcast_0 = u(&[0, 0, 0, 0, 0, 0, 0, 0]);
    let leftmost_mask_0 = u(&[0, 0, 0, 0, 0, 0, 0, 0]);
    // past_0[c] = 1 iff int_ind[c] > start_broadcast_0[c] = 0.
    let past_0 = u(&[0, 1, 1, 1, 0, 1, 1, 1]);

    // ---- Factor 1: "cd" ----
    // Only chars past the "ab" mark (past_0=1) participate. At those
    // char positions, "cd" occurs at int_ind = 2 within each string.
    let occurs_1 = u(&[0, 0, 1, 0, 0, 0, 1, 0]);
    let match_str_1 = u(&[1, 1, 0, 0, 0, 0, 0, 0]);
    let mark_1 = u(&[0, 0, 1, 0, 0, 0, 1, 0]);
    let start_1 = u(&[2, 2, 0, 0, 0, 0, 0, 0]);
    let match_broadcast_1 = u(&[1, 1, 1, 1, 1, 1, 1, 1]);
    let start_broadcast_1 = u(&[2, 2, 2, 2, 2, 2, 2, 2]);
    // leftmost_mask_1[c] = 1 iff int_ind[c] < 2.
    let leftmost_mask_1 = u(&[1, 1, 0, 0, 1, 1, 0, 0]);

    // ---- Schemas and field refs ----
    let char_f = u64_field("char");
    let orig_ind_f = u64_field("orig_ind");
    let int_ind_f = u64_field("int_ind");
    let bnd_f = u64_field("bnd");
    let ind_f = u64_field("ind");
    let flag = bool_field("data");
    let char0_f = u64_field("char_0");
    let char1_f = u64_field("char_1");
    let bnd_1_f = u64_field("bnd_1");

    let char_input_schema = Schema::new(vec![
        char_f.as_ref().clone(),
        orig_ind_f.as_ref().clone(),
        int_ind_f.as_ref().clone(),
        bnd_f.as_ref().clone(),
    ]);
    let str_input_schema = Schema::new(vec![ind_f.as_ref().clone()]);
    let flag_schema = Schema::new(vec![flag.as_ref().clone()]);
    let rot_char_schema =
        Schema::new(vec![char0_f.as_ref().clone(), char1_f.as_ref().clone()]);

    // Helper to build a per-factor rotated_char table.
    let rot_char_cols = || -> Vec<(Arc<Field>, Vec<F>)> {
        vec![
            (char0_f.clone(), char_0.clone()),
            (char1_f.clone(), char_1.clone()),
        ]
    };

    let start_f = u64_field("start");
    let match_prime_f = u64_field("match_prime");
    let start_bcast_f = u64_field("start_broadcast");
    let mask_f = u64_field("leftmost_mask");
    let past_f = u64_field("past");

    let harness = GadgetHarness::<B>::builder(16)
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
        // --- Factor 0 payload ---
        .with_table(
            gadget_id,
            &factor_label(0, "rotated_char"),
            TableSpec {
                schema: rot_char_schema.clone(),
                log_size: CHAR_NV,
                cols: rot_char_cols(),
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "occurs"),
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), occurs_0)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "match"),
            TableSpec {
                schema: flag_schema.clone(),
                log_size: STR_NV,
                cols: vec![(flag.clone(), match_str_0)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "mark"),
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), mark_0)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "start"),
            TableSpec {
                schema: Schema::new(vec![start_f.as_ref().clone()]),
                log_size: STR_NV,
                cols: vec![(start_f.clone(), start_0)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "match_broadcast"),
            TableSpec {
                schema: Schema::new(vec![match_prime_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(match_prime_f.clone(), match_broadcast_0)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "start_broadcast"),
            TableSpec {
                schema: Schema::new(vec![start_bcast_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(start_bcast_f.clone(), start_broadcast_0)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "leftmost_mask"),
            TableSpec {
                schema: Schema::new(vec![mask_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(mask_f.clone(), leftmost_mask_0)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "rotated_bnd"),
            TableSpec {
                schema: Schema::new(vec![bnd_1_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(bnd_1_f.clone(), bnd_1.clone())],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "past"),
            TableSpec {
                schema: Schema::new(vec![past_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(past_f.clone(), past_0)],
                activator: None,
            },
        )
        // --- Factor 1 payload ---
        .with_table(
            gadget_id,
            &factor_label(1, "rotated_char"),
            TableSpec {
                schema: rot_char_schema.clone(),
                log_size: CHAR_NV,
                cols: rot_char_cols(),
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(1, "occurs"),
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), occurs_1)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(1, "match"),
            TableSpec {
                schema: flag_schema.clone(),
                log_size: STR_NV,
                cols: vec![(flag.clone(), match_str_1)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(1, "mark"),
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), mark_1)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(1, "start"),
            TableSpec {
                schema: Schema::new(vec![start_f.as_ref().clone()]),
                log_size: STR_NV,
                cols: vec![(start_f.clone(), start_1)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(1, "match_broadcast"),
            TableSpec {
                schema: Schema::new(vec![match_prime_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(match_prime_f.clone(), match_broadcast_1)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(1, "start_broadcast"),
            TableSpec {
                schema: Schema::new(vec![start_bcast_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(start_bcast_f.clone(), start_broadcast_1)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(1, "leftmost_mask"),
            TableSpec {
                schema: Schema::new(vec![mask_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(mask_f.clone(), leftmost_mask_1)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(1, "rotated_bnd"),
            TableSpec {
                schema: Schema::new(vec![bnd_1_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(bnd_1_f.clone(), bnd_1.clone())],
                activator: None,
            },
        )
        .build();

    run_gadget_pipeline(harness).expect("SweepFactors t=2 two-infix should verify");
}

// -----------------------------------------------------------------------------
// parse_like_pattern
// -----------------------------------------------------------------------------

fn assert_factors(pat: &str, expected: &[(&[u8], Mode)]) {
    let got = parse_like_pattern::<F>(pat).unwrap_or_else(|e| panic!("parse `{pat}`: {e}"));
    assert_eq!(got.len(), expected.len(), "factor count for `{pat}`");
    for (i, ((got_pat, got_mode), (exp_bytes, exp_mode))) in
        got.iter().zip(expected.iter()).enumerate()
    {
        assert_eq!(got_mode, exp_mode, "mode of factor {i} for `{pat}`");
        let got_bytes: Vec<u8> = got_pat
            .iter()
            .map(|f| as_u64(*f) as u8)
            .collect();
        assert_eq!(&got_bytes, exp_bytes, "content of factor {i} for `{pat}`");
    }
}

fn as_u64(x: F) -> u64 {
    use ark_ff::{BigInteger, PrimeField};
    let bi = x.into_bigint();
    let bytes = bi.to_bytes_le();
    let mut acc = 0u64;
    for (i, b) in bytes.iter().take(8).enumerate() {
        acc |= (*b as u64) << (8 * i);
    }
    acc
}

#[test]
fn parse_like_prefix() {
    assert_factors("abc%", &[(b"abc", Mode::Prefix)]);
}

#[test]
fn parse_like_suffix() {
    assert_factors("%abc", &[(b"abc", Mode::Suffix)]);
}

#[test]
fn parse_like_infix() {
    assert_factors("%abc%", &[(b"abc", Mode::Infix)]);
}

#[test]
fn parse_like_prefix_infix_suffix() {
    assert_factors(
        "foo%bar%baz",
        &[
            (b"foo", Mode::Prefix),
            (b"bar", Mode::Infix),
            (b"baz", Mode::Suffix),
        ],
    );
}

#[test]
fn parse_like_two_infix() {
    assert_factors(
        "%foo%bar%",
        &[(b"foo", Mode::Infix), (b"bar", Mode::Infix)],
    );
}

#[test]
fn parse_like_empty_returns_empty() {
    let got = parse_like_pattern::<F>("").unwrap();
    assert!(got.is_empty(), "empty pattern should have no factors");
}

#[test]
fn parse_like_wildcard_only_returns_empty() {
    let got = parse_like_pattern::<F>("%").unwrap();
    assert!(got.is_empty());
    let got = parse_like_pattern::<F>("%%").unwrap();
    assert!(got.is_empty());
}

#[test]
fn parse_like_collapses_adjacent_wildcards() {
    // %%foo%%%bar%% behaves like %foo%bar%
    assert_factors(
        "%%foo%%%bar%%",
        &[(b"foo", Mode::Infix), (b"bar", Mode::Infix)],
    );
}

#[test]
fn parse_like_escaped_percent_is_literal() {
    // `\%` becomes a literal `%` inside the factor.
    assert_factors(r"foo\%bar%", &[(b"foo%bar", Mode::Prefix)]);
}

#[test]
fn parse_like_rejects_underscore_wildcard() {
    let err = parse_like_pattern::<F>("a_b").unwrap_err();
    assert!(err.contains("_"), "err mentions underscore: {err}");
}

#[test]
fn parse_like_no_wildcards_is_prefix() {
    // Documented limitation: falls into Prefix mode, not strict equality.
    assert_factors("abc", &[(b"abc", Mode::Prefix)]);
}

// -----------------------------------------------------------------------------
// Additional t = 2 mode variety — prefix-then-infix, using the witness
// computer to generate all per-factor columns (proves the pipeline
// works for mixed modes with a consistent bnd fixture).
// -----------------------------------------------------------------------------

#[test]
fn honest_t2_prefix_then_infix_verifies_via_witness_computer() {
    use super::witness::{ScannedTables, compute_mcpm_witness};
    const STR_NV: usize = 3;
    const CHAR_NV: usize = 3;

    let factors = vec![
        (pattern(b"ab"), Mode::Prefix),
        (pattern(b"cd"), Mode::Infix),
    ];
    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new_with_nodup_mode(
        factors.clone(),
        nodup::Mode::BezoutBased,
    ))));
    let gadget_id = gadget.id();

    let tables = ScannedTables {
        char: u(&[
            b'a' as u64, b'b' as u64, b'c' as u64, b'd' as u64,
            b'a' as u64, b'b' as u64, b'c' as u64, b'd' as u64,
        ]),
        orig_ind: u(&[0, 0, 0, 0, 1, 1, 1, 1]),
        int_ind: u(&[0, 1, 2, 3, 0, 1, 2, 3]),
        bnd: u(&[1, 0, 0, 0, 1, 0, 0, 0]),
        char_act: u(&[1, 1, 1, 1, 1, 1, 1, 1]),
        char_domain: CHAR_NV,
        ind: u(&[0, 1, 2, 3, 4, 5, 6, 7]),
        a: u(&[1, 1, 0, 0, 0, 0, 0, 0]),
        l: {
            use ark_ff::Zero;
            let two = F::from(4u64);
            vec![two, two, F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero()]
        },
        str_domain: STR_NV,
    };
    let w = compute_mcpm_witness(&tables, &factors);

    // Sanity: both strings should match.
    assert_eq!(w.a_new, u(&[1, 1, 0, 0, 0, 0, 0, 0]));

    // Wire the harness from the computed witnesses.
    let char_f = u64_field("char");
    let orig_ind_f = u64_field("orig_ind");
    let int_ind_f = u64_field("int_ind");
    let bnd_f = u64_field("bnd");
    let ind_f = u64_field("ind");
    let flag = bool_field("data");
    let char0_f = u64_field("char_0");
    let char1_f = u64_field("char_1");
    let bnd_1_f = u64_field("bnd_1");
    let start_f = u64_field("start");
    let match_prime_f = u64_field("match_prime");
    let start_bcast_f = u64_field("start_broadcast");
    let mask_f = u64_field("leftmost_mask");
    let past_f = u64_field("past");

    let char_input_schema = Schema::new(vec![
        char_f.as_ref().clone(),
        orig_ind_f.as_ref().clone(),
        int_ind_f.as_ref().clone(),
        bnd_f.as_ref().clone(),
    ]);
    let str_input_schema = Schema::new(vec![ind_f.as_ref().clone()]);
    let flag_schema = Schema::new(vec![flag.as_ref().clone()]);
    let rot_char_schema =
        Schema::new(vec![char0_f.as_ref().clone(), char1_f.as_ref().clone()]);

    let mut builder = GadgetHarness::<B>::builder(16)
        .with_gadget(gadget)
        .with_table(
            gadget_id,
            CHAR_INPUT_LABEL,
            TableSpec {
                schema: char_input_schema,
                log_size: CHAR_NV,
                cols: vec![
                    (char_f, tables.char.clone()),
                    (orig_ind_f, tables.orig_ind.clone()),
                    (int_ind_f, tables.int_ind.clone()),
                    (bnd_f, tables.bnd.clone()),
                ],
                activator: Some(tables.char_act.clone()),
            },
        )
        .with_table(
            gadget_id,
            STR_INPUT_LABEL,
            TableSpec {
                schema: str_input_schema,
                log_size: STR_NV,
                cols: vec![(ind_f, tables.ind.clone())],
                activator: Some(tables.a.clone()),
            },
        );

    for (j, fw) in w.per_factor.iter().enumerate() {
        let rot_cols: Vec<(Arc<Field>, Vec<F>)> = fw
            .rotated_chars
            .iter()
            .enumerate()
            .map(|(delta, v)| {
                (
                    Arc::new(Field::new(format!("char_{delta}"), DataType::UInt64, false)),
                    v.clone(),
                )
            })
            .collect();

        builder = builder
            .with_table(
                gadget_id,
                &factor_label(j, "rotated_char"),
                TableSpec {
                    schema: rot_char_schema.clone(),
                    log_size: CHAR_NV,
                    cols: rot_cols,
                    activator: None,
                },
            )
            .with_table(
                gadget_id,
                &factor_label(j, "occurs"),
                TableSpec {
                    schema: flag_schema.clone(),
                    log_size: CHAR_NV,
                    cols: vec![(flag.clone(), fw.occurs.clone())],
                    activator: None,
                },
            )
            .with_table(
                gadget_id,
                &factor_label(j, "match"),
                TableSpec {
                    schema: flag_schema.clone(),
                    log_size: STR_NV,
                    cols: vec![(flag.clone(), fw.match_str.clone())],
                    activator: None,
                },
            )
            .with_table(
                gadget_id,
                &factor_label(j, "mark"),
                TableSpec {
                    schema: flag_schema.clone(),
                    log_size: CHAR_NV,
                    cols: vec![(flag.clone(), fw.mark.clone())],
                    activator: None,
                },
            )
            .with_table(
                gadget_id,
                &factor_label(j, "start"),
                TableSpec {
                    schema: Schema::new(vec![start_f.as_ref().clone()]),
                    log_size: STR_NV,
                    cols: vec![(start_f.clone(), fw.start.clone())],
                    activator: None,
                },
            )
            .with_table(
                gadget_id,
                &factor_label(j, "match_broadcast"),
                TableSpec {
                    schema: Schema::new(vec![match_prime_f.as_ref().clone()]),
                    log_size: CHAR_NV,
                    cols: vec![(match_prime_f.clone(), fw.match_broadcast.clone())],
                    activator: None,
                },
            )
            .with_table(
                gadget_id,
                &factor_label(j, "start_broadcast"),
                TableSpec {
                    schema: Schema::new(vec![start_bcast_f.as_ref().clone()]),
                    log_size: CHAR_NV,
                    cols: vec![(start_bcast_f.clone(), fw.start_broadcast.clone())],
                    activator: None,
                },
            )
            .with_table(
                gadget_id,
                &factor_label(j, "leftmost_mask"),
                TableSpec {
                    schema: Schema::new(vec![mask_f.as_ref().clone()]),
                    log_size: CHAR_NV,
                    cols: vec![(mask_f.clone(), fw.leftmost_mask.clone())],
                    activator: None,
                },
            );

        if let Some(ref rb) = fw.rotated_bnd {
            // Only one rotated_bnd col for ℓ = 2.
            builder = builder.with_table(
                gadget_id,
                &factor_label(j, "rotated_bnd"),
                TableSpec {
                    schema: Schema::new(vec![bnd_1_f.as_ref().clone()]),
                    log_size: CHAR_NV,
                    cols: vec![(bnd_1_f.clone(), rb[0].clone())],
                    activator: None,
                },
            );
        }
        if let Some(ref past) = fw.past {
            builder = builder.with_table(
                gadget_id,
                &factor_label(j, "past"),
                TableSpec {
                    schema: Schema::new(vec![past_f.as_ref().clone()]),
                    log_size: CHAR_NV,
                    cols: vec![(past_f.clone(), past.clone())],
                    activator: None,
                },
            );
        }
    }

    let harness = builder.build();
    run_gadget_pipeline(harness)
        .expect("SweepFactors t=2 prefix+infix should verify with computed witnesses");
}

// -----------------------------------------------------------------------------
// Malicious-prover soundness tests for SweepFactors
// -----------------------------------------------------------------------------

/// Malicious mask: swap `past_0` to something that lies about
/// `int_ind > start'`. The Sign gadget should reject.
#[test]
fn malicious_past_wrong_flags_rejected() {
    const STR_NV: usize = 3;
    const CHAR_NV: usize = 3;

    let factors = vec![
        (pattern(b"ab"), Mode::Infix),
        (pattern(b"cd"), Mode::Infix),
    ];
    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new_with_nodup_mode(
        factors.clone(),
        nodup::Mode::BezoutBased,
    ))));
    let gadget_id = gadget.id();

    use super::witness::{ScannedTables, compute_mcpm_witness};
    let tables = ScannedTables {
        char: u(&[
            b'a' as u64, b'b' as u64, b'c' as u64, b'd' as u64,
            b'a' as u64, b'b' as u64, b'c' as u64, b'd' as u64,
        ]),
        orig_ind: u(&[0, 0, 0, 0, 1, 1, 1, 1]),
        int_ind: u(&[0, 1, 2, 3, 0, 1, 2, 3]),
        bnd: u(&[1, 0, 0, 0, 1, 0, 0, 0]),
        char_act: u(&[1, 1, 1, 1, 1, 1, 1, 1]),
        char_domain: CHAR_NV,
        ind: u(&[0, 1, 2, 3, 4, 5, 6, 7]),
        a: u(&[1, 1, 0, 0, 0, 0, 0, 0]),
        l: {
            use ark_ff::Zero;
            let four = F::from(4u64);
            vec![four, four, F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero()]
        },
        str_domain: STR_NV,
    };
    let mut w = compute_mcpm_witness(&tables, &factors);

    // Flip past_0 to the wrong value at position c=0. Honest is 0 (int_ind
    // = 0 is NOT > start_broadcast = 0), attacker claims 1. This should
    // fail the NonNegative Sign check: sign_input at c=0 becomes
    //   1 * (0 - 0 - 1) + 0 * (0 - 0) = -1 < 0.
    let past = w.per_factor[0].past.as_mut().unwrap();
    past[0] = F::from(1u64);

    // Wire and expect failure.
    let harness = wire_from_witness(&tables, &w, gadget, gadget_id, STR_NV, CHAR_NV);
    assert!(
        run_gadget_pipeline(harness).is_err(),
        "malicious past_0 flip should be rejected"
    );
}

/// Malicious mask: swap `leftmost_mask_1` to lie about `int_ind <
/// start'`. Sign gadget should reject.
#[test]
fn malicious_leftmost_mask_wrong_flags_rejected() {
    const STR_NV: usize = 3;
    const CHAR_NV: usize = 3;

    let factors = vec![
        (pattern(b"ab"), Mode::Infix),
        (pattern(b"cd"), Mode::Infix),
    ];
    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new_with_nodup_mode(
        factors.clone(),
        nodup::Mode::BezoutBased,
    ))));
    let gadget_id = gadget.id();

    use super::witness::{ScannedTables, compute_mcpm_witness};
    let tables = ScannedTables {
        char: u(&[
            b'a' as u64, b'b' as u64, b'c' as u64, b'd' as u64,
            b'a' as u64, b'b' as u64, b'c' as u64, b'd' as u64,
        ]),
        orig_ind: u(&[0, 0, 0, 0, 1, 1, 1, 1]),
        int_ind: u(&[0, 1, 2, 3, 0, 1, 2, 3]),
        bnd: u(&[1, 0, 0, 0, 1, 0, 0, 0]),
        char_act: u(&[1, 1, 1, 1, 1, 1, 1, 1]),
        char_domain: CHAR_NV,
        ind: u(&[0, 1, 2, 3, 4, 5, 6, 7]),
        a: u(&[1, 1, 0, 0, 0, 0, 0, 0]),
        l: {
            use ark_ff::Zero;
            let four = F::from(4u64);
            vec![four, four, F::zero(), F::zero(), F::zero(), F::zero(), F::zero(), F::zero()]
        },
        str_domain: STR_NV,
    };
    let mut w = compute_mcpm_witness(&tables, &factors);
    // At c=2 in factor 1, int_ind=2 == start_broadcast=2, so mask is
    // honest 0. Flip to 1 (attacker claims 2 < 2). Sign_input = 1 *
    // (2 - 2 - 1) + 0 * (2 - 2) = -1 → Sign should reject.
    w.per_factor[1].leftmost_mask[2] = F::from(1u64);

    let harness = wire_from_witness(&tables, &w, gadget, gadget_id, STR_NV, CHAR_NV);
    assert!(
        run_gadget_pipeline(harness).is_err(),
        "malicious leftmost_mask flip should be rejected"
    );
}

/// Wire a full SweepFactors harness (t = 2 fixture, two infix factors)
/// from computed witnesses. Extracted so the malicious-prover tests can
/// tweak individual witness columns.
fn wire_from_witness(
    tables: &super::witness::ScannedTables<F>,
    w: &super::witness::McpmWitness<F>,
    gadget: Arc<Node<B>>,
    gadget_id: crate::irs::nodes::NodeId,
    str_nv: usize,
    char_nv: usize,
) -> crate::test_utils::gadget_harness::GadgetHarness<B> {
    let char_f = u64_field("char");
    let orig_ind_f = u64_field("orig_ind");
    let int_ind_f = u64_field("int_ind");
    let bnd_f = u64_field("bnd");
    let ind_f = u64_field("ind");
    let flag = bool_field("data");
    let char0_f = u64_field("char_0");
    let char1_f = u64_field("char_1");
    let bnd_1_f = u64_field("bnd_1");
    let start_f = u64_field("start");
    let match_prime_f = u64_field("match_prime");
    let start_bcast_f = u64_field("start_broadcast");
    let mask_f = u64_field("leftmost_mask");
    let past_f = u64_field("past");

    let char_input_schema = Schema::new(vec![
        char_f.as_ref().clone(),
        orig_ind_f.as_ref().clone(),
        int_ind_f.as_ref().clone(),
        bnd_f.as_ref().clone(),
    ]);
    let str_input_schema = Schema::new(vec![ind_f.as_ref().clone()]);
    let flag_schema = Schema::new(vec![flag.as_ref().clone()]);
    let rot_char_schema =
        Schema::new(vec![char0_f.as_ref().clone(), char1_f.as_ref().clone()]);

    let mut builder = GadgetHarness::<B>::builder(16)
        .with_gadget(gadget)
        .with_table(
            gadget_id,
            CHAR_INPUT_LABEL,
            TableSpec {
                schema: char_input_schema,
                log_size: char_nv,
                cols: vec![
                    (char_f, tables.char.clone()),
                    (orig_ind_f, tables.orig_ind.clone()),
                    (int_ind_f, tables.int_ind.clone()),
                    (bnd_f, tables.bnd.clone()),
                ],
                activator: Some(tables.char_act.clone()),
            },
        )
        .with_table(
            gadget_id,
            STR_INPUT_LABEL,
            TableSpec {
                schema: str_input_schema,
                log_size: str_nv,
                cols: vec![(ind_f, tables.ind.clone())],
                activator: Some(tables.a.clone()),
            },
        );

    for (j, fw) in w.per_factor.iter().enumerate() {
        let rot_cols: Vec<(Arc<Field>, Vec<F>)> = fw
            .rotated_chars
            .iter()
            .enumerate()
            .map(|(delta, v)| {
                (
                    Arc::new(Field::new(format!("char_{delta}"), DataType::UInt64, false)),
                    v.clone(),
                )
            })
            .collect();

        builder = builder
            .with_table(
                gadget_id,
                &factor_label(j, "rotated_char"),
                TableSpec {
                    schema: rot_char_schema.clone(),
                    log_size: char_nv,
                    cols: rot_cols,
                    activator: None,
                },
            )
            .with_table(
                gadget_id,
                &factor_label(j, "occurs"),
                TableSpec {
                    schema: flag_schema.clone(),
                    log_size: char_nv,
                    cols: vec![(flag.clone(), fw.occurs.clone())],
                    activator: None,
                },
            )
            .with_table(
                gadget_id,
                &factor_label(j, "match"),
                TableSpec {
                    schema: flag_schema.clone(),
                    log_size: str_nv,
                    cols: vec![(flag.clone(), fw.match_str.clone())],
                    activator: None,
                },
            )
            .with_table(
                gadget_id,
                &factor_label(j, "mark"),
                TableSpec {
                    schema: flag_schema.clone(),
                    log_size: char_nv,
                    cols: vec![(flag.clone(), fw.mark.clone())],
                    activator: None,
                },
            )
            .with_table(
                gadget_id,
                &factor_label(j, "start"),
                TableSpec {
                    schema: Schema::new(vec![start_f.as_ref().clone()]),
                    log_size: str_nv,
                    cols: vec![(start_f.clone(), fw.start.clone())],
                    activator: None,
                },
            )
            .with_table(
                gadget_id,
                &factor_label(j, "match_broadcast"),
                TableSpec {
                    schema: Schema::new(vec![match_prime_f.as_ref().clone()]),
                    log_size: char_nv,
                    cols: vec![(match_prime_f.clone(), fw.match_broadcast.clone())],
                    activator: None,
                },
            )
            .with_table(
                gadget_id,
                &factor_label(j, "start_broadcast"),
                TableSpec {
                    schema: Schema::new(vec![start_bcast_f.as_ref().clone()]),
                    log_size: char_nv,
                    cols: vec![(start_bcast_f.clone(), fw.start_broadcast.clone())],
                    activator: None,
                },
            )
            .with_table(
                gadget_id,
                &factor_label(j, "leftmost_mask"),
                TableSpec {
                    schema: Schema::new(vec![mask_f.as_ref().clone()]),
                    log_size: char_nv,
                    cols: vec![(mask_f.clone(), fw.leftmost_mask.clone())],
                    activator: None,
                },
            );

        if let Some(ref rb) = fw.rotated_bnd {
            builder = builder.with_table(
                gadget_id,
                &factor_label(j, "rotated_bnd"),
                TableSpec {
                    schema: Schema::new(vec![bnd_1_f.as_ref().clone()]),
                    log_size: char_nv,
                    cols: vec![(bnd_1_f.clone(), rb[0].clone())],
                    activator: None,
                },
            );
        }
        if let Some(ref past) = fw.past {
            builder = builder.with_table(
                gadget_id,
                &factor_label(j, "past"),
                TableSpec {
                    schema: Schema::new(vec![past_f.as_ref().clone()]),
                    log_size: char_nv,
                    cols: vec![(past_f.clone(), past.clone())],
                    activator: None,
                },
            );
        }
    }
    builder.build()
}

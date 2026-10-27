//! The Lexicographic Sortedness Check on up to eight strings, through a
//! gadget that calls it inline, alone and chained with integer sort keys.

use std::sync::Arc;

use arithmetic::ACTIVATOR_FIELD;
use ark_ff::Zero;
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, errors::SnarkError, verifier::errors::VerifierError,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{IDS_PER_POSITION, Witness, prove_with_witness, rotate, verify, witness};
use crate::irs::nodes::{
    Node,
    utils::{
        contig_sort::{
            ACTIVE_ROWS_LABEL, rotation,
            tests::{active_rows, assert_rejected},
        },
        lex_sort::{
            data_oracles, data_polys,
            piop::{self as lex, SortKey, Tie},
            sortedness::{self, CHARS_LABEL, GadgetNode, STRINGS_LABEL},
        },
    },
};
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};
use crate::test_utils::inline_gadget::InlineGadget;

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

pub(crate) const ROW_NV: usize = 3;
pub(crate) const CHAR_NV: usize = 4;
const STRINGS: &str = "strings";
const CHARS: &str = "chars";
const BEFORE: &str = "before";
const AFTER: &str = "after";

pub(crate) fn int(v: i64) -> F {
    F::from(v)
}

/// A collision-free stand-in for the hash: the bytes at even and at odd
/// positions, each read as base-257 digits shifted by one. An inline-short
/// column has one slot holding the first byte, as the encoder writes it.
pub(crate) fn hash(s: &[u8], inline_short: bool) -> Vec<F> {
    if inline_short {
        return vec![int(s.first().map_or(0, |&b| i64::from(b)))];
    }
    (0..2)
        .map(|parity| {
            s.iter()
                .skip(parity)
                .step_by(2)
                .rev()
                .fold(F::from(0u64), |acc, &b| {
                    acc * F::from(257u64) + F::from(u64::from(b) + 1)
                })
        })
        .collect()
}

/// `values` on the rows, zero beyond them.
pub(crate) fn padded(values: Vec<F>, log_size: usize) -> Vec<F> {
    let mut values = values;
    values.resize(1 << log_size, F::from(0u64));
    values
}

pub(crate) fn spec(
    log_size: usize,
    columns: Vec<(String, Vec<F>)>,
    activator: Option<Vec<F>>,
) -> TableSpec<F> {
    let fields: Vec<Arc<Field>> = columns
        .iter()
        .map(|(name, _)| Arc::new(Field::new(name, DataType::UInt64, false)))
        .collect();
    let mut schema: Vec<Field> = fields.iter().map(|f| f.as_ref().clone()).collect();
    if activator.is_some() {
        schema.push(ACTIVATOR_FIELD.as_ref().clone());
    }
    TableSpec {
        schema: Schema::new(schema),
        log_size,
        cols: fields
            .into_iter()
            .zip(
                columns
                    .into_iter()
                    .map(|(_, values)| padded(values, log_size)),
            )
            .collect(),
        activator: activator.map(|a| padded(a, log_size)),
    }
}

/// The character table of `owners` on `2^log_size` rows: string `o` owns
/// the characters with `orig-ind = o`, all active.
pub(crate) fn char_table(owners: &[&[u8]], log_size: usize) -> TableSpec<F> {
    let mut columns = [Vec::new(), Vec::new(), Vec::new()];
    for (o, s) in owners.iter().enumerate() {
        for (k, &c) in s.iter().enumerate() {
            columns[0].push(int(o as i64));
            columns[1].push(int(k as i64));
            columns[2].push(int(i64::from(c)));
        }
    }
    let active = vec![int(1); columns[0].len()];
    let [orig_ind, int_ind, chars] = columns;
    spec(
        log_size,
        vec![
            ("orig_ind".to_string(), orig_ind),
            ("int_ind".to_string(), int_ind),
            ("char".to_string(), chars),
        ],
        Some(active),
    )
}

fn integer_key(values: &[i64]) -> TableSpec<F> {
    let data: Vec<F> = padded(values.iter().map(|v| int(*v)).collect(), ROW_NV);
    let next = rotate(&data);
    spec(
        ROW_NV,
        vec![("key".to_string(), data), ("next".to_string(), next)],
        None,
    )
}

struct Run {
    asc: bool,
    inline_short: bool,
    /// `index[i]` owns row `i`'s characters; the identity by default.
    index: Option<Vec<usize>>,
    /// An integer key sorted before the strings, whose `t_m` is `t_in`.
    before: Option<Vec<i64>>,
    /// An integer key sorted after the strings, from the returned `same`.
    after: Option<Vec<i64>>,
    forge: fn(&mut Witness<F>),
    expected_same: Option<Vec<i64>>,
    /// The character table's owners in place of the strings themselves.
    chars: Option<Vec<&'static [u8]>>,
    char_log_size: usize,
    /// Tracker ids spent on both sides before the check.
    ids_before: usize,
    /// Asserts that the verifier spends at most `(R + 1)·IDS_PER_POSITION`
    /// tracker ids on the check, for this `R`.
    positions: Option<usize>,
}

impl Default for Run {
    fn default() -> Self {
        Self {
            asc: true,
            inline_short: false,
            index: None,
            before: None,
            after: None,
            forge: |_| {},
            expected_same: None,
            chars: None,
            char_log_size: CHAR_NV,
            ids_before: 0,
            positions: None,
        }
    }
}

/// Checks the column of `strings` on its first `strings.len()` rows.
fn run(strings: &[&[u8]], opts: Run) -> Result<(), SnarkError> {
    let n = strings.len();
    let index = opts.index.clone().unwrap_or_else(|| (0..n).collect());
    let mut owners: Vec<&[u8]> = vec![b""; n];
    for (i, &o) in index.iter().enumerate() {
        owners[o] = strings[i];
    }
    if let Some(chars) = &opts.chars {
        owners.clone_from(chars);
    }
    let slots = hash(b"", opts.inline_short).len();
    let mut columns = vec![(
        "index".to_string(),
        index.iter().map(|&o| int(o as i64)).collect(),
    )];
    for slot in 0..slots {
        let values = strings
            .iter()
            .map(|s| hash(s, opts.inline_short)[slot])
            .collect();
        columns.push((format!("hash_{slot}"), values));
    }
    columns.push((
        "length".to_string(),
        strings.iter().map(|s| int(s.len() as i64)).collect(),
    ));
    let (asc, forge, ids_before, positions) =
        (opts.asc, opts.forge, opts.ids_before, opts.positions);
    let expected_same = opts
        .expected_same
        .map(|same| padded(same.iter().map(|v| int(*v)).collect(), ROW_NV));
    let width = 8;

    let gadget = InlineGadget::<B>::node(
        Box::new(move |prover, payload| {
            while prover.peek_next_id().to_int() < ids_before {
                prover.track_mat_mv_cnst_poly(0, F::zero());
            }
            let (column, chars) = sortedness::columns(
                data_polys(&payload[STRINGS]),
                data_polys(&payload[CHARS]),
                payload[CHARS].activator_tracked_poly().expect("char-act"),
            );
            let mut tie = Tie::mask(prover, ROW_NV, n)?;
            if let Some(table) = payload.get(BEFORE) {
                let [data, next] = data_polys(table).try_into().expect("key and next");
                rotation::prove(prover, &[(data.clone(), next.clone())], ROW_NV, n)?;
                let key = SortKey {
                    data,
                    next,
                    asc: true,
                    width,
                };
                tie = lex::prove(prover, &[key], tie, false)?;
            }
            let mut committed = witness(&column, &chars, &tie, &[])?;
            forge(&mut committed);
            let output = prove_with_witness(prover, &column, &chars, tie, &[], asc, committed)?;
            if let Some(expected) = &expected_same {
                assert_eq!(&output.same.poly().evaluations(), expected);
            }
            if let Some(table) = payload.get(AFTER) {
                let [data, next] = data_polys(table).try_into().expect("key and next");
                rotation::prove(prover, &[(data.clone(), next.clone())], ROW_NV, n)?;
                let key = SortKey {
                    data,
                    next,
                    asc: true,
                    width,
                };
                lex::prove(prover, &[key], output.same, false)?;
            }
            Ok(())
        }),
        Box::new(move |verifier, payload| {
            while verifier.peek_next_id().to_int() < ids_before {
                verifier.track_mat_mv_cnst_oracle(0, F::zero());
            }
            let (column, chars) = sortedness::columns(
                data_oracles(&payload[STRINGS]),
                data_oracles(&payload[CHARS]),
                payload[CHARS].activator_tracked_poly().expect("char-act"),
            );
            let mut tie = Tie::mask_oracle(verifier, ROW_NV, n)?;
            if let Some(table) = payload.get(BEFORE) {
                let [data, next] = data_oracles(table).try_into().expect("key and next");
                rotation::verify(verifier, &[(data.clone(), next.clone())], ROW_NV, n)?;
                let key = SortKey {
                    data,
                    next,
                    asc: true,
                    width,
                };
                tie = lex::verify(verifier, &[key], tie, false)?;
            }
            let start = verifier.peek_next_id().to_int();
            let output = verify(verifier, &column, &chars, tie, &[], asc)?;
            if let Some(r) = positions {
                let spent = verifier.peek_next_id().to_int() - start;
                assert!(
                    spent <= (r + 1) * IDS_PER_POSITION,
                    "R = {r} cost the verifier {spent} tracker ids"
                );
            }
            if let Some(table) = payload.get(AFTER) {
                let [data, next] = data_oracles(table).try_into().expect("key and next");
                rotation::verify(verifier, &[(data.clone(), next.clone())], ROW_NV, n)?;
                let key = SortKey {
                    data,
                    next,
                    asc: true,
                    width,
                };
                lex::verify(verifier, &[key], output.same, false)?;
            }
            Ok(())
        }),
    );
    let id = gadget.id();
    let mut builder = GadgetHarness::<B>::builder(16)
        .with_gadget(gadget)
        .with_table(id, STRINGS, spec(ROW_NV, columns, None))
        .with_table(id, CHARS, char_table(&owners, opts.char_log_size));
    if let Some(values) = &opts.before {
        builder = builder.with_table(id, BEFORE, integer_key(values));
    }
    if let Some(values) = &opts.after {
        builder = builder.with_table(id, AFTER, integer_key(values));
    }
    run_gadget_pipeline(builder.build())
}

/// The same rows shifted down by one, undoing the honest rotation.
fn unrotate(column: &mut [F]) {
    column.rotate_right(1);
}

#[test]
fn ties_prefixes_and_empty_strings_accepted() {
    let strings: [&[u8]; 8] = [b"", b"", b"a", b"ab", b"abc", b"abd", b"b", b"b"];
    let opts = Run {
        expected_same: Some(vec![1, 0, 0, 0, 0, 0, 1, 0]),
        ..Run::default()
    };
    run(&strings, opts).expect("a sorted column verifies");
}

#[test]
fn descending_order() {
    let strings: [&[u8]; 6] = [b"b", b"abd", b"abc", b"ab", b"a", b""];
    let desc = || Run {
        asc: false,
        ..Run::default()
    };
    run(&strings, desc()).expect("a descending column verifies descending");
    assert_rejected(run(&strings, Run::default()));
    assert_rejected(run(&[b"", b"a", b"ab"], desc()));
}

#[test]
fn all_equal_strings_need_no_position() {
    let opts = Run {
        expected_same: Some(vec![1, 1, 1, 0]),
        ..Run::default()
    };
    run(&[b"xy", b"xy", b"xy", b"xy"], opts).expect("R = 0 when every pair is equal");
}

#[test]
fn one_and_two_rows() {
    run(&[b"q"], Run::default()).expect("one row has no pair");
    run(&[b"a", b"b"], Run::default()).expect("two sorted rows verify");
    assert_rejected(run(&[b"b", b"a"], Run::default()));
}

#[test]
fn constant_witnesses_accepted() {
    // Every row is active and distinct, so `same ≡ 0`, and every string
    // starts with `a`, so `c_0` and its rotation are constant too.
    let strings: [&[u8]; 8] = [b"ab", b"ac", b"ad", b"ae", b"af", b"ag", b"ah", b"ai"];
    run(&strings, Run::default()).expect("constant committed columns verify");
}

#[test]
fn characters_through_a_source_index() {
    // Row `i`'s characters are owned by `index[i]`, as when the column is a
    // sorted copy of another whose characters are reused.
    let index = || Some(vec![2, 0, 3, 1]);
    let opts = || Run {
        index: index(),
        ..Run::default()
    };
    run(&[b"a", b"ab", b"b", b"ba"], opts()).expect("a sorted column verifies");
    assert_rejected(run(&[b"a", b"b", b"ab", b"ba"], opts()));
}

#[test]
fn unsorted_column_rejected() {
    assert_rejected(run(&[b"b", b"a", b"c"], Run::default()));
    assert_rejected(run(&[b"abd", b"abc"], Run::default()));
    assert_rejected(run(&[b"abc", b"ab"], Run::default()));
}

#[test]
fn chained_with_integer_keys() {
    // ORDER BY k, s: the strings are compared only within ties of `k`.
    let before = |k: &[i64]| Run {
        before: Some(k.to_vec()),
        ..Run::default()
    };
    run(&[b"b", b"c", b"a"], before(&[1, 1, 2])).expect("sorted within k's ties");
    assert_rejected(run(&[b"c", b"b", b"a"], before(&[1, 1, 2])));
    // ORDER BY s, k: `k` is compared only within ties of the strings.
    let after = |k: &[i64]| Run {
        after: Some(k.to_vec()),
        ..Run::default()
    };
    run(&[b"a", b"a", b"b"], after(&[1, 2, 0])).expect("sorted within the strings' ties");
    assert_rejected(run(&[b"a", b"a", b"b"], after(&[2, 1, 0])));
}

#[test]
fn inline_short_empty_and_nul_strings() {
    // Both strings hash to slot 0; only their lengths tell them apart.
    let short = |forge: fn(&mut Witness<F>)| Run {
        inline_short: true,
        forge,
        ..Run::default()
    };
    run(&[b"", b"\0"], short(|_| {})).expect("\"\" < \"\\0\" verifies");
    assert_rejected(run(&[b"\0", b""], short(|_| {})));
    assert_rejected(run(
        &[b"\0", b""],
        short(|w| {
            w.same[0] = int(1);
            w.projections.clear();
            w.projections_next.clear();
        }),
    ));
}

#[test]
fn forged_same_on_distinct_strings_rejected() {
    let opts = Run {
        forge: |w| {
            w.same[0] = int(1);
            w.projections.clear();
            w.projections_next.clear();
        },
        ..Run::default()
    };
    assert_rejected(run(&[b"b", b"a"], opts));
}

#[test]
fn forged_distinct_on_equal_strings_rejected() {
    let opts = Run {
        forge: |w| w.same[0] = int(0),
        ..Run::default()
    };
    assert_rejected(run(&[b"a", b"a", b"b"], opts));
}

#[test]
fn too_few_positions_rejected() {
    // "abc" and "abd" first differ at position 2, so R = 3.
    let opts = Run {
        forge: |w| {
            w.projections.truncate(2);
            w.projections_next.truncate(2);
        },
        ..Run::default()
    };
    run(&[b"abc", b"abd"], Run::default()).expect("R = 3 verifies");
    assert_rejected(run(&[b"abc", b"abd"], opts));
}

#[test]
fn unrotated_columns_with_no_position_rejected() {
    // Claiming every pair equal, with h^next = h and l^next = l, satisfies
    // every step-2 zerocheck and leaves no pair for the strict check; only
    // the Rotation Check, which runs although R = 0, rejects it.
    let opts = Run {
        forge: |w| {
            w.same[0] = int(1);
            w.same[1] = int(1);
            for column in &mut w.hash_next {
                unrotate(column);
            }
            unrotate(&mut w.length_next);
            w.projections.clear();
            w.projections_next.clear();
        },
        ..Run::default()
    };
    assert_rejected(run(&[b"b", b"a", b"c"], opts));
}

#[test]
fn forged_projection_rejected() {
    // Swapping the first characters of "b" and "a" would order them.
    let opts = Run {
        forge: |w| {
            w.projections[0][0] = int(i64::from(b'a'));
            w.projections[0][1] = int(i64::from(b'b'));
            w.projections_next[0] = rotate(&w.projections[0]);
        },
        ..Run::default()
    };
    assert_rejected(run(&[b"b", b"a"], opts));
}

#[test]
fn forged_rotated_projection_rejected() {
    let opts = Run {
        forge: |w| w.projections_next[0][0] = int(i64::from(b'c')),
        ..Run::default()
    };
    assert_rejected(run(&[b"b", b"a"], opts));
}

/// The column of `strings` through the [`GadgetNode`], with the public
/// identity as its index.
fn run_gadget(strings: &[&[u8]], asc: bool) -> Result<(), SnarkError> {
    let rows = 1 << ROW_NV;
    let mut columns = vec![(
        "index".to_string(),
        (0..rows).map(|i| int(i as i64)).collect(),
    )];
    for slot in 0..2 {
        let values = strings.iter().map(|s| hash(s, false)[slot]).collect();
        columns.push((format!("hash_{slot}"), values));
    }
    columns.push((
        "length".to_string(),
        strings.iter().map(|s| int(s.len() as i64)).collect(),
    ));
    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(asc))));
    let id = gadget.id();
    let harness = GadgetHarness::<B>::builder(16)
        .with_gadget(gadget)
        .with_table(id, STRINGS_LABEL, spec(ROW_NV, columns, None))
        .with_table(id, CHARS_LABEL, char_table(strings, CHAR_NV))
        .with_table(id, ACTIVE_ROWS_LABEL, active_rows(strings.len() as u64))
        .build();
    run_gadget_pipeline(harness)
}

#[test]
fn through_the_gadget_node() {
    let strings: [&[u8]; 5] = [b"", b"a", b"a", b"ab", b"b"];
    run_gadget(&strings, true).expect("a sorted column verifies");
    assert_rejected(run_gadget(&strings, false));
    assert_rejected(run_gadget(&[b"ab", b"a"], true));
}

#[test]
fn more_positions_than_the_longest_string_rejected() {
    // Positions past every string only add equal `⊥` projections, so every
    // claim holds; the verifier refuses the count before tracking them.
    let opts = Run {
        forge: |w| padded_positions(w, (1 << CHAR_NV) + 2),
        ..Run::default()
    };
    let result = run(&[b"a", b"b"], opts);
    assert!(
        matches!(result, Err(SnarkError::VerifierError(_))),
        "expected the verifier to refuse the position count, got {result:?}"
    );
}

#[test]
fn same_outside_the_tie_rejected() {
    // `same` must stay within `t_in`, on padding rows and on pairs an
    // earlier key separated, or the tie it hands on would compare rows the
    // Rotation Check leaves free.
    let padding = Run {
        forge: |w| w.same[5] = int(1),
        ..Run::default()
    };
    assert_rejected(run(&[b"a", b"b"], padding));
    let separated = Run {
        before: Some(vec![1, 2]),
        forge: |w| w.same[0] = int(1),
        ..Run::default()
    };
    assert_rejected(run(&[b"a", b"a"], separated));
}

#[test]
fn non_boolean_same_rejected() {
    // `same = 2` on the equal pair makes `t_in·(1 − same) = −1`, which the
    // strict check's range check on `(c'_0 − c_0 − 1)·(−1) = 1` accepts.
    let opts = Run {
        forge: |w| w.same[0] = int(2),
        ..Run::default()
    };
    assert_rejected(run(&[b"a", b"a", b"b"], opts));
}

#[test]
fn unmarked_hash_equal_pair_rejected() {
    // The character table gives the second "a" the character `b`, so the
    // strict check alone accepts the pair as `a < b`; only NoZero forces
    // `same` on a pair whose hash slots and length agree.
    let opts = Run {
        chars: Some(vec![b"a", b"b"]),
        forge: |w| {
            w.same[0] = int(0);
            let mut first = vec![int(-1); w.same.len()];
            first[0] = int(i64::from(b'a'));
            first[1] = int(i64::from(b'b'));
            w.projections_next = vec![rotate(&first)];
            w.projections = vec![first];
        },
        ..Run::default()
    };
    assert_rejected(run(&[b"a", b"a"], opts));
}

/// Pads the projections with `⊥` columns up to `positions`.
fn padded_positions(w: &mut Witness<F>, positions: usize) {
    let rows = w.same.len();
    w.projections.resize(positions, vec![int(-1); rows]);
    w.projections_next.resize(positions, vec![int(-1); rows]);
}

#[test]
fn tracker_ids_per_position_within_the_bound() {
    let measured = |positions: usize| Run {
        positions: Some(positions),
        ..Run::default()
    };
    run(&[b"xy", b"xy", b"xy"], measured(0)).expect("R = 0 verifies");
    run(&[b"abc", b"abd"], measured(3)).expect("R = 3 verifies");
    let wide = Run {
        char_log_size: 16,
        ..measured(3)
    };
    run(&[b"abc", b"abd"], wide).expect("R = 3 over a wide character domain verifies");
    let most = Run {
        forge: |w| padded_positions(w, (1 << CHAR_NV) + 1),
        ..measured((1 << CHAR_NV) + 1)
    };
    run(&[b"a", b"b"], most).expect("the most positions the cap allows verify");
}

#[test]
fn positions_exhausting_the_tracker_ids_rejected() {
    // The check would fit, but with 2000 ids left the verifier cannot
    // reserve `(R + 1)·IDS_PER_POSITION` of them, and refuses rather than
    // risk ark-piop's panic on overflowing the ids.
    let opts = Run {
        ids_before: usize::from(u16::MAX) - 2000,
        forge: |w| padded_positions(w, (1 << CHAR_NV) + 1),
        ..Run::default()
    };
    let result = run(&[b"a", b"b"], opts);
    assert!(
        matches!(
            &result,
            Err(SnarkError::VerifierError(VerifierError::VerifierCheckFailed(message)))
                if message.contains("tracker ids")
        ),
        "expected the verifier to refuse the position count, got {result:?}"
    );
}

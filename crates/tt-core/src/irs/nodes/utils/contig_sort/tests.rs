//! Tests for `ContigSort` (paper PIOP 7) on hand-built tables of four rows.
//!
//! The harness skips gadget planning, so each test supplies the hint tables
//! itself. A forged hint reaches prover and verifier alike, as a committed
//! witness does in a real proof.

use std::sync::Arc;

use arithmetic::ACTIVATOR_FIELD;
use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{
    ACTIVE_ROWS_LABEL, GadgetNode, LIMBS_LABEL, PerColumnConfig, ROTATED_INPUT_LABEL, SortConfig,
    TABLE_LABEL, TIE_INDICATOR_LABEL,
};
use crate::irs::nodes::Node;
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};
use arithmetic::encoding::{encode_arrow_array_to_field, hash_slot_limb_widths, hash_slot_limbs};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const NV: usize = 2;

fn ints(vs: &[i64]) -> Vec<F> {
    vs.iter().map(|v| F::from(*v as i128)).collect()
}

fn rotate(xs: &[F]) -> Vec<F> {
    (0..xs.len()).map(|i| xs[(i + 1) % xs.len()]).collect()
}

fn distinct() -> SortConfig {
    SortConfig::Distinct
}

fn ascending(keys: &[&str], strict: bool) -> SortConfig {
    SortConfig::PerColumn(PerColumnConfig {
        sort_specs: keys
            .iter()
            .map(|key| (key.to_string(), true, false))
            .collect(),
        strict,
    })
}

fn table(cols: &[(&str, DataType, Vec<F>)], activator: Option<Vec<F>>) -> TableSpec<F> {
    let fields: Vec<Arc<Field>> = cols
        .iter()
        .map(|(name, data_type, _)| Arc::new(Field::new(*name, data_type.clone(), false)))
        .collect();
    let mut schema_fields: Vec<Field> = fields.iter().map(|field| field.as_ref().clone()).collect();
    if activator.is_some() {
        schema_fields.push(ACTIVATOR_FIELD.as_ref().clone());
    }
    TableSpec {
        schema: Schema::new(schema_fields),
        log_size: NV,
        cols: fields
            .into_iter()
            .zip(cols.iter().map(|(_, _, values)| values.clone()))
            .collect(),
        activator,
    }
}

/// The active-row count `s` the sort check reads, as a committed scalar.
pub(crate) fn active_rows(s: u64) -> TableSpec<F> {
    let field = Arc::new(Field::new("active_rows", DataType::UInt64, false));
    TableSpec {
        schema: Schema::new(vec![field.as_ref().clone()]),
        log_size: 0,
        cols: vec![(field, vec![F::from(s)])],
        activator: None,
    }
}

/// Proves and verifies that `keys` (all rows active) is sorted under
/// `config`, with the given committed tie hints.
pub(crate) fn run(
    config: SortConfig,
    keys: &[(&str, DataType, Vec<F>)],
    ties: &[(&str, Vec<F>)],
) -> Result<(), ark_piop::errors::SnarkError> {
    let rotated: Vec<_> = keys.iter().map(|(_, _, values)| rotate(values)).collect();
    run_with(config, keys, &rotated, 4, ties)
}

/// As [`run`], with the first `s` rows active and the shifted copy `d'` of
/// each key given.
fn run_with(
    config: SortConfig,
    keys: &[(&str, DataType, Vec<F>)],
    shifted: &[Vec<F>],
    s: u64,
    ties: &[(&str, Vec<F>)],
) -> Result<(), ark_piop::errors::SnarkError> {
    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(config))));
    let id = gadget.id();
    let active = (0..4).map(|row| F::from(u64::from(row < s))).collect();
    let rotated: Vec<_> = keys
        .iter()
        .zip(shifted)
        .map(|((name, data_type, _), values)| (*name, data_type.clone(), values.clone()))
        .collect();

    let mut builder = GadgetHarness::<B>::builder(16)
        .with_gadget(gadget)
        .with_table(id, TABLE_LABEL, table(keys, Some(active)))
        .with_table(id, ROTATED_INPUT_LABEL, table(&rotated, None))
        .with_table(id, ACTIVE_ROWS_LABEL, active_rows(s));
    if !ties.is_empty() {
        let ties: Vec<_> = ties
            .iter()
            .map(|(name, values)| (*name, DataType::Boolean, values.clone()))
            .collect();
        builder = builder.with_table(id, TIE_INDICATOR_LABEL, table(&ties, None));
    }
    run_gadget_pipeline(builder.build())
}

/// With `honest-prover` the prover refuses the false claim before the
/// verifier sees it.
pub(crate) fn assert_rejected(result: Result<(), ark_piop::errors::SnarkError>) {
    use ark_piop::errors::SnarkError;
    use ark_piop::prover::errors::{HonestProverError, ProverError};
    let rejected = if cfg!(feature = "honest-prover") {
        matches!(
            result,
            Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::FalseClaim
            )))
        )
    } else {
        matches!(result, Err(SnarkError::VerifierError(_)))
    };
    assert!(
        rejected,
        "expected the proof to be rejected, got {result:?}"
    );
}

#[test]
fn distinct_ascending_keys_accepted() {
    let keys = [("k", DataType::Int64, ints(&[1, 3, 5, 9]))];
    run(distinct(), &keys, &[]).expect("a strictly sorted key column verifies");
}

#[test]
fn duplicate_with_zero_first_tie_rejected() {
    // An all-zero tie_0 switches off every comparison; the gadget must use
    // the public mask instead.
    let keys = [("k", DataType::Int64, ints(&[1, 5, 5, 9]))];
    let ties = [("tie_0", ints(&[0, 0, 0, 0]))];
    assert_rejected(run(distinct(), &keys, &ties));
}

#[test]
fn duplicate_rejected() {
    let keys = [("k", DataType::Int64, ints(&[1, 5, 5, 9]))];
    assert_rejected(run(distinct(), &keys, &[]));
}

#[test]
fn inversion_rejected() {
    let keys = [("k", DataType::Int64, ints(&[1, 7, 3, 9]))];
    assert_rejected(run(ascending(&["k"], false), &keys, &[]));
}

#[test]
fn signed_extremes_accepted() {
    // Adjacent differences up to 2^64 - 1 need the unsigned 64-bit width.
    let keys = [("k", DataType::Int64, ints(&[i64::MIN, -1, 0, i64::MAX]))];
    run(ascending(&["k"], false), &keys, &[]).expect("sorted signed keys verify");
}

#[test]
fn ties_broken_by_second_key_accepted() {
    let keys = [
        ("a", DataType::Int32, ints(&[1, 1, 2, 2])),
        ("b", DataType::Int32, ints(&[3, 4, 1, 5])),
    ];
    let ties = [("tie_1", ints(&[1, 0, 1, 0]))];
    run(ascending(&["a", "b"], true), &keys, &ties)
        .expect("a lexicographically strict table verifies");
}

#[test]
fn duplicate_row_with_two_keys_rejected() {
    let keys = [
        ("a", DataType::Int32, ints(&[1, 1, 2, 2])),
        ("b", DataType::Int32, ints(&[3, 3, 1, 5])),
    ];
    let ties = [("tie_1", ints(&[1, 0, 1, 0]))];
    assert_rejected(run(ascending(&["a", "b"], true), &keys, &ties));
}

#[test]
fn a_key_without_an_ordered_encoding_is_not_supported() {
    // A string's hash says nothing about its order: its rank is sorted
    // instead.
    let keys = [("s", DataType::Utf8, ints(&[10, 20, 30, 40]))];
    let result = run(ascending(&["s"], false), &keys, &[]);
    assert!(
        matches!(
            result,
            Err(ark_piop::errors::SnarkError::DataTypeError(
                ark_piop::arithmetic::errors::DataTypeError::NotSupported(_)
            ))
        ),
        "got {result:?}"
    );
}

#[test]
fn a_key_must_name_exactly_one_column() {
    let keys = [("t.k", DataType::Int64, ints(&[1, 2, 3, 4]))];
    for spec in ["k", "t.k2"] {
        let result = run(ascending(&[spec], false), &keys, &[]);
        assert!(
            matches!(
                result,
                Err(ark_piop::errors::SnarkError::DataTypeError(
                    ark_piop::arithmetic::errors::DataTypeError::NotSupported(_)
                ))
            ),
            "{spec}: got {result:?}"
        );
    }
}

#[test]
fn ties_follow_key_order_not_column_order() {
    // Columns [a, b], sorted by (b, a): `tie_1` means "tied on b", so the
    // rows where it is set must agree on b, not on a.
    let keys = [
        ("a", DataType::Int64, ints(&[1, 2, 0, 5])),
        ("b", DataType::Int64, ints(&[1, 1, 3, 3])),
    ];
    let ties = [("tie_1", ints(&[1, 0, 1, 0]))];
    run(ascending(&["b", "a"], false), &keys, &ties)
        .expect("a table sorted by a key order unlike its column order verifies");
}

#[test]
fn tie_hint_covers_only_the_sort_keys() {
    use datafusion::arrow::array::{ArrayRef, BooleanArray, Int64Array};
    use datafusion::arrow::record_batch::RecordBatch;

    // Sorted by (b, a) with a payload column p: the hint has one tie column,
    // "tied on b", over the rows in (b, a) order.
    let batch = RecordBatch::try_from_iter(vec![
        (
            "a",
            Arc::new(Int64Array::from(vec![2, 5, 1, 0])) as ArrayRef,
        ),
        (
            "b",
            Arc::new(Int64Array::from(vec![1, 3, 1, 3])) as ArrayRef,
        ),
        (
            "p",
            Arc::new(Int64Array::from(vec![7, 7, 9, 9])) as ArrayRef,
        ),
    ])
    .unwrap();
    let df = crate::session::session_context().read_batch(batch).unwrap();
    let should_materialize = df
        .schema()
        .fields()
        .iter()
        .map(|field| (field.clone(), true))
        .collect();
    let input = crate::irs::nodes::hints::HintDF::new(df, should_materialize);
    let specs = vec![
        ("b".to_string(), true, false),
        ("a".to_string(), true, false),
    ];

    let mut payload = indexmap::IndexMap::new();
    super::hints::populate_ties(&mut payload, &input, &specs);

    let tie_df = payload[TIE_INDICATOR_LABEL].data_frame().clone();
    let batches = crate::session::block_on(tie_df.collect()).unwrap();
    assert_eq!(batches[0].num_columns(), 1);
    let tie_1 = batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<BooleanArray>()
        .unwrap();
    // Rows in order: (a, b) = (1, 1), (2, 1), (0, 3), (5, 3).
    assert_eq!(
        tie_1.iter().collect::<Vec<_>>(),
        vec![Some(true), Some(false), Some(true), Some(false)]
    );
}

#[test]
fn non_monotone_ties_are_rejected() {
    // Row 0 claims ties [1, 0, 1, 0]: two tie breaks, at `a` and at `c`, which
    // hides `b`, out of order (9 > 1), from every range check. Tie
    // monotonicity is not checked (paper Lemma "checker soundness"): the
    // break at `a`, where the rows are equal, fails its own nonzero check.
    // A single nonzero claim over all columns would accept this row, since
    // `c` does differ.
    let keys = [
        ("a", DataType::Int64, ints(&[5, 5, 6, 7])),
        ("b", DataType::Int64, ints(&[9, 1, 0, 0])),
        ("c", DataType::Int64, ints(&[0, 1, 0, 0])),
        ("d", DataType::Int64, ints(&[0, 0, 0, 0])),
    ];
    let ties = [
        ("tie_1", ints(&[0, 0, 0, 0])),
        ("tie_2", ints(&[1, 0, 0, 0])),
        ("tie_3", ints(&[0, 0, 0, 0])),
    ];
    assert_rejected(run(ascending(&["a", "b", "c", "d"], false), &keys, &ties));
}

#[test]
fn rows_past_the_active_ones_are_not_compared() {
    // Three active rows; the padding row is smaller than the last of them.
    let keys = [("k", DataType::Int64, ints(&[1, 2, 3, 0]))];
    let shifted = [ints(&[2, 3, 0, 1])];
    run_with(ascending(&["k"], false), &keys, &shifted, 3, &[])
        .expect("only the active prefix is sorted");
}

#[test]
fn the_last_shifted_row_is_free() {
    // `d'[j] = d[j + 1]` is required only for `j < s - 1`: no wrap-around.
    let keys = [("k", DataType::Int64, ints(&[1, 2, 3, 4]))];
    let shifted = [ints(&[2, 3, 4, 999])];
    run_with(ascending(&["k"], false), &keys, &shifted, 4, &[])
        .expect("the last row of d' is never read");
}

#[test]
fn a_forged_shift_is_rejected() {
    // 5 > 1 at rows 0, 1. A d' that is not d shifted, chosen so every
    // difference is non-negative, must fail the multiset equality. That
    // equality is checked by the verifier in both builds: the harness skips
    // the pipeline's honest-prover pass, which holds its prover-side check.
    let keys = [("k", DataType::Int64, ints(&[5, 1, 7, 9]))];
    let shifted = [ints(&[6, 7, 9, 0])];
    let result = run_with(ascending(&["k"], false), &keys, &shifted, 4, &[]);
    assert!(
        matches!(result, Err(ark_piop::errors::SnarkError::VerifierError(_))),
        "expected the verifier to reject, got {result:?}"
    );
}

/// The distinct sort of a string column whose rows hold `strings`' hash
/// slots, the first `s` active, with the given limbs per row (most
/// significant first) and honest ties over them.
fn run_distinct_strings(
    strings: &[&str],
    limbs: Vec<Vec<u64>>,
    s: u64,
) -> Result<(), ark_piop::errors::SnarkError> {
    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(distinct()))));
    let id = gadget.id();
    let widths = hash_slot_limb_widths::<F>();
    let limb_cols: Vec<(String, DataType, Vec<F>)> = widths
        .iter()
        .enumerate()
        .map(|(j, width)| {
            let dtype = if *width == 8 {
                DataType::UInt8
            } else {
                DataType::UInt16
            };
            let values = limbs.iter().map(|row| F::from(row[j])).collect();
            (format!("s_limb{j}"), dtype, values)
        })
        .collect();
    let limb_spec: Vec<(&str, DataType, Vec<F>)> = limb_cols
        .iter()
        .map(|(name, dtype, values)| (name.as_str(), dtype.clone(), values.clone()))
        .collect();
    let rotated: Vec<(&str, DataType, Vec<F>)> = limb_spec
        .iter()
        .map(|(name, dtype, values)| (*name, dtype.clone(), rotate(values)))
        .collect();
    let tie_names: Vec<String> = (1..widths.len()).map(|k| format!("tie_{k}")).collect();
    let ties: Vec<(&str, DataType, Vec<F>)> = tie_names
        .iter()
        .enumerate()
        .map(|(idx, name)| {
            let values = (0..4)
                .map(|row| {
                    let tied = row < 3 && limbs[row][..=idx] == limbs[row + 1][..=idx];
                    F::from(u64::from(tied))
                })
                .collect();
            (name.as_str(), DataType::Boolean, values)
        })
        .collect();
    let slots = (
        "s",
        DataType::Utf8,
        strings.iter().map(|s| hash_slot(s)).collect(),
    );
    let builder = GadgetHarness::<B>::builder(16)
        .with_gadget(gadget)
        .with_table(
            id,
            TABLE_LABEL,
            table(
                &[slots],
                Some((0..4).map(|row| F::from(u64::from(row < s))).collect()),
            ),
        )
        .with_table(id, LIMBS_LABEL, table(&limb_spec, None))
        .with_table(id, ROTATED_INPUT_LABEL, table(&rotated, None))
        .with_table(id, TIE_INDICATOR_LABEL, table(&ties, None))
        .with_table(id, ACTIVE_ROWS_LABEL, active_rows(s));
    run_gadget_pipeline(builder.build())
}

fn hash_slot(string: &str) -> F {
    let array: datafusion::arrow::array::ArrayRef =
        Arc::new(datafusion::arrow::array::StringArray::from(vec![
            string, "pad",
        ]));
    encode_arrow_array_to_field::<F>(&array).unwrap()[0]
        .iter_values()
        .next()
        .unwrap()
}

fn honest_limbs(string: &str) -> Vec<u64> {
    hash_slot_limbs(hash_slot(string))
        .into_iter()
        .map(u64::from)
        .collect()
}

/// Four strings in the order of their hash limbs.
fn strings_in_limb_order() -> Vec<&'static str> {
    let mut strings = vec!["FRANCE", "GERMANY", "JAPAN", "PERU"];
    strings.sort_by_key(|s| honest_limbs(s));
    strings
}

#[test]
fn distinct_strings_sorted_on_their_hash_limbs_verify() {
    let strings = strings_in_limb_order();
    let limbs = strings.iter().map(|s| honest_limbs(s)).collect();
    run_distinct_strings(&strings, limbs, 4).expect("distinct hashes sorted on their limbs verify");
}

#[test]
fn a_duplicated_string_is_rejected() {
    let mut strings = strings_in_limb_order();
    strings[1] = strings[0];
    let limbs = strings.iter().map(|s| honest_limbs(s)).collect();
    assert_rejected(run_distinct_strings(&strings, limbs, 4));
}

#[test]
fn a_duplicated_string_with_forged_limbs_is_rejected() {
    // The copy's limbs sort above the original's, but do not recompose its
    // hash.
    let mut strings = strings_in_limb_order();
    strings[1] = strings[0];
    let mut limbs: Vec<Vec<u64>> = strings.iter().map(|s| honest_limbs(s)).collect();
    *limbs[1].last_mut().unwrap() += 1;
    assert!(limbs[0] < limbs[1] && limbs[1] < limbs[2]);
    assert_rejected(run_distinct_strings(&strings, limbs, 4));
}

#[test]
fn a_duplicated_string_with_a_borrowed_limb_is_rejected() {
    // The first copy borrows 1 from its top limb into the next one: the limbs
    // still recompose the hash and sort below the honest copy's, with an
    // in-range difference of 1 at the top limb. Only the range check on the
    // limbs themselves rejects the second limb, 2^16 too large.
    let string = ["FRANCE", "GERMANY", "JAPAN", "PERU"]
        .into_iter()
        .find(|s| honest_limbs(s)[0] > 0)
        .expect("a hash with a nonzero top limb");
    let honest = honest_limbs(string);
    let mut borrowed = honest.clone();
    borrowed[0] -= 1;
    borrowed[1] += 1 << 16;
    let limbs = vec![borrowed, honest.clone(), honest.clone(), honest];
    assert_rejected(run_distinct_strings(&[string; 4], limbs, 2));
}

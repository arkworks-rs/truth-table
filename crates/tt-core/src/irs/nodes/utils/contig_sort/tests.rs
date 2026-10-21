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
    DIFF_INPUT_LABEL, GadgetNode, PerColumnConfig, ROTATED_INPUT_LABEL, SortConfig, TABLE_LABEL,
    TIE_INDICATOR_LABEL, UniformConfig,
};
use crate::irs::nodes::Node;
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const NV: usize = 2;

fn ints(vs: &[i64]) -> Vec<F> {
    vs.iter().map(|v| F::from(*v as i128)).collect()
}

fn rotate(xs: &[F]) -> Vec<F> {
    (0..xs.len()).map(|i| xs[(i + 1) % xs.len()]).collect()
}

/// The strict descending sort that `NoDup` runs.
fn nodup_config() -> SortConfig {
    SortConfig::Uniform(UniformConfig {
        asc: false,
        strict: true,
    })
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

/// Proves and verifies that `keys` (all rows active) is sorted under
/// `config`, with the given committed tie and diff hints.
fn run(
    config: SortConfig,
    keys: &[(&str, DataType, Vec<F>)],
    ties: &[(&str, Vec<F>)],
    diffs: &[(&str, DataType, Vec<F>)],
) -> Result<(), ark_piop::errors::SnarkError> {
    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(config))));
    let id = gadget.id();
    let active = ints(&[1, 1, 1, 1]);
    let rotated: Vec<_> = keys
        .iter()
        .map(|(name, data_type, values)| (*name, data_type.clone(), rotate(values)))
        .collect();

    let mut builder = GadgetHarness::<B>::builder(16)
        .with_gadget(gadget)
        .with_table(id, TABLE_LABEL, table(keys, Some(active.clone())))
        .with_table(id, ROTATED_INPUT_LABEL, table(&rotated, Some(active)));
    if !ties.is_empty() {
        let ties: Vec<_> = ties
            .iter()
            .map(|(name, values)| (*name, DataType::Boolean, values.clone()))
            .collect();
        builder = builder.with_table(id, TIE_INDICATOR_LABEL, table(&ties, None));
    }
    if !diffs.is_empty() {
        builder = builder.with_table(id, DIFF_INPUT_LABEL, table(diffs, None));
    }
    run_gadget_pipeline(builder.build())
}

/// With `honest-prover` the prover refuses the false claim before the
/// verifier sees it.
fn assert_rejected(result: Result<(), ark_piop::errors::SnarkError>) {
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
fn distinct_descending_keys_accepted() {
    let keys = [("k", DataType::Int64, ints(&[9, 5, 3, 1]))];
    run(nodup_config(), &keys, &[], &[]).expect("a strictly sorted key column verifies");
}

#[test]
fn duplicate_with_zero_first_tie_rejected() {
    // An all-zero tie_0 switches off every comparison; the gadget must use
    // the public mask instead.
    let keys = [("k", DataType::Int64, ints(&[5, 5, 3, 1]))];
    let ties = [("tie_0", ints(&[0, 0, 0, 0]))];
    let diffs = [("k", DataType::Int64, ints(&[0, 2, 2, -4]))];
    assert_rejected(run(nodup_config(), &keys, &ties, &diffs));
}

#[test]
fn duplicate_with_forged_diff_rejected() {
    // The true difference of the duplicate pair is 0; a committed 1 must
    // not reach the Sign check.
    let keys = [("k", DataType::Int64, ints(&[5, 5, 3, 1]))];
    let ties = [("tie_0", ints(&[1, 1, 1, 0]))];
    let diffs = [("k", DataType::Int64, ints(&[1, 2, 2, 0]))];
    assert_rejected(run(nodup_config(), &keys, &ties, &diffs));
}

#[test]
fn inversion_with_forged_diff_rejected() {
    let keys = [("k", DataType::Int64, ints(&[1, 7, 3, 9]))];
    let ties = [("tie_0", ints(&[1, 1, 1, 0]))];
    let diffs = [("k", DataType::Int64, ints(&[6, 1, 6, 0]))];
    assert_rejected(run(ascending(&["k"], false), &keys, &ties, &diffs));
}

#[test]
fn signed_extremes_accepted() {
    // Adjacent differences up to 2^64 - 1 need the unsigned 64-bit width.
    let keys = [("k", DataType::Int64, ints(&[i64::MIN, -1, 0, i64::MAX]))];
    run(ascending(&["k"], false), &keys, &[], &[]).expect("sorted signed keys verify");
}

#[test]
fn ties_broken_by_second_key_accepted() {
    let keys = [
        ("a", DataType::Int32, ints(&[1, 1, 2, 2])),
        ("b", DataType::Int32, ints(&[3, 4, 1, 5])),
    ];
    let ties = [("tie_1", ints(&[1, 0, 1, 0]))];
    run(ascending(&["a", "b"], true), &keys, &ties, &[])
        .expect("a lexicographically strict table verifies");
}

#[test]
fn duplicate_row_with_two_keys_rejected() {
    let keys = [
        ("a", DataType::Int32, ints(&[1, 1, 2, 2])),
        ("b", DataType::Int32, ints(&[3, 3, 1, 5])),
    ];
    let ties = [("tie_1", ints(&[1, 0, 1, 0]))];
    assert_rejected(run(ascending(&["a", "b"], true), &keys, &ties, &[]));
}

#[test]
fn sign_only_key_uses_committed_diff() {
    // String keys have no order-preserving encoding; they are compared
    // through the committed shifted sign {0, 1, 2}.
    let keys = [("s", DataType::Utf8, ints(&[40, 10, 30, 20]))];
    let diffs = [("s", DataType::UInt8, ints(&[2, 2, 2, 0]))];
    run(ascending(&["s"], false), &keys, &[], &diffs).expect("a sign-only key verifies");
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
    run(ascending(&["b", "a"], false), &keys, &ties, &[])
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
    super::hints::populate_tie_and_diff(&mut payload, &input, &specs);

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
    // Row 0 claims ties [1, 0, 1, 0]: two tie breaks, at `a` and at `c`. The
    // neq check folds every column's break into one claim, so it only proves
    // that `a` or `c` differs there (`c` does), while `b`, out of order
    // (9 > 1), is never range-checked. Tie monotonicity is what rules out two
    // breaks in one row and so makes the folded check per-column.
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
    assert_rejected(run(
        ascending(&["a", "b", "c", "d"], false),
        &keys,
        &ties,
        &[],
    ));
}

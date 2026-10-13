//! Prefix ties must describe the configured sort keys, in their configured order.
//!
//! All fixtures supply truthful rotations, differences, and the public non-wrap
//! mask. These regressions are independent of the separate mask/difference fixes.

use std::sync::Arc;

use ark_piop::{DefaultSnarkBackend, SnarkBackend, errors::assert_soundness_error};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{
    DIFF_INPUT_LABEL, GadgetNode, PerColumnConfig, ROTATED_INPUT_LABEL, SortConfig, TABLE_LABEL,
    TIE_INDICATOR_LABEL,
};
use crate::{
    irs::nodes::Node,
    test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline},
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

fn table(columns: &[(String, Vec<i64>)], active: bool, ties: bool) -> TableSpec<F> {
    let row_count = columns[0].1.len();
    assert!(row_count.is_power_of_two());
    assert!(columns.iter().all(|(_, values)| values.len() == row_count));
    let cols = columns
        .iter()
        .map(|(name, values)| {
            let field = Arc::new(Field::new(
                name,
                if ties {
                    DataType::Boolean
                } else {
                    DataType::Int8
                },
                false,
            ));
            (field, values.iter().copied().map(F::from).collect())
        })
        .collect::<Vec<_>>();
    let mut fields = cols
        .iter()
        .map(|(field, _)| field.clone())
        .collect::<Vec<_>>();
    if active {
        fields.push(arithmetic::ACTIVATOR_FIELD.clone());
    }
    TableSpec {
        schema: Schema::new(fields),
        log_size: row_count.ilog2() as usize,
        cols,
        activator: active.then(|| vec![F::from(1u64); row_count]),
    }
}

fn harness(
    columns: &[(&str, &[i64])],
    sort_keys: &[(&str, bool)],
    strict: bool,
) -> GadgetHarness<B> {
    assert!(!sort_keys.is_empty());
    let columns = columns
        .iter()
        .map(|(name, values)| (name.to_string(), values.to_vec()))
        .collect::<Vec<_>>();
    let row_count = columns[0].1.len();
    let rotated = columns
        .iter()
        .map(|(name, values)| {
            let mut values = values.clone();
            values.rotate_left(1);
            (name.clone(), values)
        })
        .collect::<Vec<_>>();
    let differences = columns
        .iter()
        .zip(&rotated)
        .map(|((name, current), (_, next))| {
            let asc = sort_keys
                .iter()
                .find(|(key, _)| *key == name.as_str())
                .map(|(_, asc)| *asc)
                .unwrap_or(true);
            let values = current
                .iter()
                .zip(next)
                .map(|(current, next)| if asc { next - current } else { current - next })
                .collect();
            (name.clone(), values)
        })
        .collect::<Vec<_>>();
    // Multi-key hints omit tie_0; ContiguousSort derives it publicly. A
    // single-key hint carries that same truthful mask, as upstream expects.
    let prefix_lengths = if sort_keys.len() == 1 {
        vec![0]
    } else {
        (1..sort_keys.len()).collect()
    };
    let ties = prefix_lengths
        .into_iter()
        .map(|prefix| {
            let values = (0..row_count)
                .map(|row| {
                    i64::from(
                        row + 1 < row_count
                            && sort_keys.iter().take(prefix).all(|(key, _)| {
                                let (_, values) = columns
                                    .iter()
                                    .find(|(name, _)| name.as_str() == *key)
                                    .expect("test key must name a physical column");
                                values[row] == values[row + 1]
                            }),
                    )
                })
                .collect();
            (format!("tie_{prefix}"), values)
        })
        .collect::<Vec<_>>();
    let sort_specs = sort_keys
        .iter()
        .map(|(name, asc)| (name.to_string(), *asc, false))
        .collect();
    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(
        SortConfig::PerColumn(PerColumnConfig { sort_specs, strict }),
    ))));
    let id = gadget.id();
    GadgetHarness::<B>::builder(8)
        .with_gadget(gadget)
        .with_table(id, TABLE_LABEL, table(&columns, true, false))
        .with_table(id, ROTATED_INPUT_LABEL, table(&rotated, true, false))
        .with_table(id, DIFF_INPUT_LABEL, table(&differences, false, false))
        .with_table(id, TIE_INDICATOR_LABEL, table(&ties, false, true))
        .build()
}

fn assert_false_sort_rejected(harness: GadgetHarness<B>) {
    #[cfg(not(feature = "honest-prover"))]
    let error = crate::test_utils::gadget_harness::run_gadget_pipeline_to_verifier(harness)
        .expect("an invalid order with well-shaped witnesses must reach verification")
        .expect_err("the verifier must reject an inversion in the configured key order");
    #[cfg(feature = "honest-prover")]
    let error = run_gadget_pipeline(harness)
        .expect_err("honest-prover diagnostics must reject an invalid sort");
    assert_soundness_error(error);
}

#[test]
fn key_order_accepts_reordered_keys_with_equal_primary_key() {
    // Schema [a,b], order [b,a]: b ties while a increases. Previously the
    // tie equality constraint incorrectly required a itself to stay equal.
    run_gadget_pipeline(harness(
        &[("a", &[1, 2]), ("b", &[1, 1])],
        &[("b", true), ("a", true)],
        false,
    ))
    .unwrap();
}

#[test]
fn key_order_allows_secondary_key_reset_between_primary_groups() {
    run_gadget_pipeline(harness(
        &[("a", &[1, 2, 0, 1]), ("b", &[1, 1, 2, 2])],
        &[("b", true), ("a", true)],
        true,
    ))
    .unwrap();
}

#[test]
fn key_order_accepts_mixed_directions() {
    run_gadget_pipeline(harness(
        &[("a", &[4, 3, 2, 1]), ("b", &[1, 1, 2, 2])],
        &[("b", true), ("a", false)],
        true,
    ))
    .unwrap();
}

#[test]
fn key_order_accepts_three_reordered_keys() {
    run_gadget_pipeline(harness(
        &[
            ("c", &[1, 2, 0, 0]),
            ("a", &[1, 1, 2, 0]),
            ("b", &[1, 1, 1, 2]),
        ],
        &[("b", true), ("a", true), ("c", true)],
        true,
    ))
    .unwrap();
}

#[test]
fn key_order_ignores_columns_not_named_as_sort_keys() {
    run_gadget_pipeline(harness(
        &[
            ("payload", &[4, 3, 2, 1]),
            ("a", &[1, 2, 0, 1]),
            ("b", &[1, 1, 2, 2]),
        ],
        &[("b", true), ("a", true)],
        true,
    ))
    .unwrap();
}

#[test]
fn key_order_accepts_a_single_key_from_a_wider_schema() {
    run_gadget_pipeline(harness(
        &[("payload", &[4, 3, 2, 1]), ("b", &[1, 2, 3, 4])],
        &[("b", true)],
        true,
    ))
    .unwrap();
}

#[test]
fn key_order_rejects_a_primary_key_inversion() {
    assert_false_sort_rejected(harness(
        &[("a", &[1, 2]), ("b", &[2, 1])],
        &[("b", true), ("a", true)],
        false,
    ));
}

#[test]
fn key_order_rejects_a_secondary_key_inversion_within_a_tie() {
    assert_false_sort_rejected(harness(
        &[("a", &[2, 1]), ("b", &[1, 1])],
        &[("b", true), ("a", true)],
        false,
    ));
}

#[test]
fn key_order_rejects_the_wrong_secondary_direction() {
    assert_false_sort_rejected(harness(
        &[("a", &[1, 2]), ("b", &[1, 1])],
        &[("b", true), ("a", false)],
        false,
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn key_order_hint_generation_uses_only_the_selected_keys_in_order() {
    use datafusion::{
        arrow::{
            array::{BooleanArray, Int8Array, StringArray},
            compute::concat_batches,
            record_batch::RecordBatch,
        },
        prelude::SessionContext,
    };
    use indexmap::IndexMap;

    let schema = Arc::new(Schema::new(vec![
        Field::new("payload", DataType::Utf8, false),
        Field::new("a", DataType::Int8, false),
        Field::new("b", DataType::Int8, false),
    ]));
    let batch = RecordBatch::try_new(
        schema,
        vec![
            Arc::new(StringArray::from(vec!["four", "three", "two", "one"])),
            Arc::new(Int8Array::from(vec![0, 1, 1, 2])),
            Arc::new(Int8Array::from(vec![2, 2, 1, 1])),
        ],
    )
    .unwrap();
    let df = SessionContext::new().read_batch(batch).unwrap();
    let hint = crate::irs::nodes::hints::HintDF::new_materialized(df);
    let sort_specs = vec![
        ("b".to_string(), true, false),
        ("a".to_string(), true, false),
    ];

    // The unselected string payload must not send these integer keys through
    // the window-expression subtraction path instead of explicit differences.
    assert!(super::hints::has_only_explicit_diff_types(hint.data_frame(), &sort_specs).unwrap());

    let sorted = super::hints::sort_input_for_contig_sort(&hint, &sort_specs).unwrap();
    let batches = sorted.collect().await.unwrap();
    let sorted = concat_batches(&batches[0].schema(), &batches).unwrap();
    let payload = sorted
        .column_by_name("payload")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(
        payload.iter().collect::<Vec<_>>(),
        vec![Some("two"), Some("one"), Some("four"), Some("three")]
    );

    let mut hints = IndexMap::new();
    super::hints::populate_tie_and_diff(&mut hints, &hint, &sort_specs);
    let diff_fields = hints[DIFF_INPUT_LABEL]
        .data_frame()
        .schema()
        .fields()
        .iter()
        .map(|field| field.name().as_str())
        .collect::<Vec<_>>();
    assert_eq!(diff_fields, vec!["b", "a"]);
    let differences = hints[DIFF_INPUT_LABEL]
        .data_frame()
        .clone()
        .collect()
        .await
        .unwrap();
    let differences = concat_batches(&differences[0].schema(), &differences).unwrap();
    assert_eq!(differences.num_columns(), 2);
    assert_eq!(differences.num_rows(), 4);
    let ties = hints[TIE_INDICATOR_LABEL]
        .data_frame()
        .clone()
        .collect()
        .await
        .unwrap();
    let ties = concat_batches(&ties[0].schema(), &ties).unwrap();
    assert_eq!(ties.num_columns(), 1);
    assert_eq!(ties.schema().field(0).name(), "tie_1");
    let tie = ties
        .column(0)
        .as_any()
        .downcast_ref::<BooleanArray>()
        .unwrap();
    assert_eq!(
        tie.values().iter().collect::<Vec<_>>(),
        vec![true, false, true, false]
    );

    // The verifier derives the same hint shape without looking at row values.
    let ordered = super::ordered_data_fields_for_hint(&hint, &sort_specs);
    assert_eq!(
        ordered
            .iter()
            .map(|field| field.name().as_str())
            .collect::<Vec<_>>(),
        vec!["b", "a"]
    );
    let verifier_hint = super::build_verifier_tie_hint_from_ordered(&ordered);
    assert_eq!(verifier_hint.data_frame().schema().fields().len(), 1);
    assert_eq!(verifier_hint.data_frame().schema().field(0).name(), "tie_1");
}

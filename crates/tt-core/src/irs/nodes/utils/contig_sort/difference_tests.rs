//! Actual composite-gadget proofs, with honest tie masks but untrusted
//! adjacent-difference commitments. Without `honest-prover`, forged hints
//! must reach and fail the verifier (not just an honest witness precheck).

use std::sync::Arc;

use arithmetic::ACTIVATOR_FIELD;
use ark_piop::{DefaultSnarkBackend, SnarkBackend, errors::SnarkError};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{
    DIFF_INPUT_LABEL, GadgetNode, PerColumnConfig, ROTATED_INPUT_LABEL, SortConfig, TABLE_LABEL,
    TIE_INDICATOR_LABEL, UniformConfig, checked_difference_type,
};
use crate::irs::nodes::Node;
use crate::test_utils::gadget_harness::{
    GadgetHarness, TableSpec, run_gadget_pipeline_to_verifier,
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

fn values(numbers: &[i64]) -> Vec<F> {
    numbers
        .iter()
        .map(|&number| {
            if number < 0 {
                -F::from(number.unsigned_abs())
            } else {
                F::from(number as u64)
            }
        })
        .collect()
}

fn table(name: &str, data_type: DataType, data: Vec<F>, active: Option<Vec<F>>) -> TableSpec<F> {
    assert!(data.len().is_power_of_two());
    let field = Arc::new(Field::new(name, data_type, false));
    let mut fields = vec![field.clone()];
    if active.is_some() {
        fields.push(ACTIVATOR_FIELD.clone());
    }
    TableSpec {
        schema: Schema::new(fields),
        log_size: data.len().ilog2() as usize,
        cols: vec![(field, data)],
        activator: active,
    }
}

fn run_staged(
    input: &[i64],
    difference: &[i64],
    active: Option<&[i64]>,
    asc: bool,
    strict: bool,
) -> Result<Result<(), SnarkError>, SnarkError> {
    let node = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(
        SortConfig::Uniform(UniformConfig { asc, strict }),
    ))));
    let id = node.id();
    let mut rotated = values(input);
    rotated.rotate_left(1);
    let active_values = active.map(values);
    let rotated_active = active_values.as_ref().map(|active| {
        let mut rotated = active.clone();
        rotated.rotate_left(1);
        rotated
    });
    // Single-key tie_0 is exactly the legitimate non-wrap comparison mask.
    // This keeps the separate initial-tie bug out of these regressions.
    let mut ties = vec![F::from(1u64); input.len()];
    ties[input.len() - 1] = F::from(0u64);
    let harness = GadgetHarness::<B>::builder(8)
        .with_gadget(node)
        .with_table(
            id,
            TABLE_LABEL,
            table("key", DataType::Int8, values(input), active_values),
        )
        .with_table(
            id,
            ROTATED_INPUT_LABEL,
            table("key", DataType::Int8, rotated, rotated_active),
        )
        .with_table(
            id,
            DIFF_INPUT_LABEL,
            table("key", DataType::Decimal128(20, 0), values(difference), None),
        )
        .with_table(
            id,
            TIE_INDICATOR_LABEL,
            table("tie_0", DataType::Boolean, ties, None),
        )
        .build();
    run_gadget_pipeline_to_verifier(harness)
}

fn run(
    input: &[i64],
    difference: &[i64],
    active: Option<&[i64]>,
    asc: bool,
    strict: bool,
) -> Result<(), SnarkError> {
    run_staged(input, difference, active, asc, strict)?
}

fn two_column_table(
    first: (&str, &[i64]),
    second: (&str, &[i64]),
    data_type: DataType,
    active: bool,
) -> TableSpec<F> {
    assert_eq!(first.1.len(), second.1.len());
    let mut spec = table(
        first.0,
        data_type.clone(),
        values(first.1),
        active.then(|| vec![F::from(1u64); first.1.len()]),
    );
    spec.cols.push((
        Arc::new(Field::new(second.0, data_type, false)),
        values(second.1),
    ));
    let mut fields = spec
        .cols
        .iter()
        .map(|(field, _)| field.clone())
        .collect::<Vec<_>>();
    if active {
        fields.push(ACTIVATOR_FIELD.clone());
    }
    spec.schema = Schema::new(fields);
    spec
}

/// Order the first key ASC and the second DESC, with truthful prefix ties.
fn run_two_key_staged(
    first: &[i64],
    second: &[i64],
    second_difference: &[i64],
) -> Result<Result<(), SnarkError>, SnarkError> {
    let node = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(
        SortConfig::PerColumn(PerColumnConfig {
            sort_specs: vec![
                ("first".into(), true, false),
                ("second".into(), false, false),
            ],
            strict: true,
        }),
    ))));
    let id = node.id();
    let mut rotated_first = first.to_vec();
    rotated_first.rotate_left(1);
    let mut rotated_second = second.to_vec();
    rotated_second.rotate_left(1);
    let first_difference = rotated_first
        .iter()
        .zip(first)
        .map(|(next, current)| next - current)
        .collect::<Vec<_>>();
    let mut first_tie = vec![1; first.len()];
    first_tie[first.len() - 1] = 0;
    let prefix_tie = first
        .iter()
        .zip(&rotated_first)
        .zip(&first_tie)
        .map(|((current, next), non_wrap)| i64::from(current == next) * non_wrap)
        .collect::<Vec<_>>();
    let harness = GadgetHarness::<B>::builder(8)
        .with_gadget(node)
        .with_table(
            id,
            TABLE_LABEL,
            two_column_table(("first", first), ("second", second), DataType::Int8, true),
        )
        .with_table(
            id,
            ROTATED_INPUT_LABEL,
            two_column_table(
                ("first", &rotated_first),
                ("second", &rotated_second),
                DataType::Int8,
                true,
            ),
        )
        .with_table(
            id,
            DIFF_INPUT_LABEL,
            two_column_table(
                ("first", &first_difference),
                ("second", second_difference),
                DataType::Decimal128(20, 0),
                false,
            ),
        )
        .with_table(
            id,
            TIE_INDICATOR_LABEL,
            two_column_table(
                ("tie_0", &first_tie),
                ("tie_1", &prefix_tie),
                DataType::Boolean,
                false,
            ),
        )
        .build();
    run_gadget_pipeline_to_verifier(harness)
}

fn rejects_at_verifier(result: Result<Result<(), SnarkError>, SnarkError>) {
    #[cfg(not(feature = "honest-prover"))]
    let error = result
        .expect("forged hints must reach the verifier")
        .expect_err("a forged adjacent difference must not verify");
    #[cfg(not(feature = "honest-prover"))]
    assert!(
        matches!(error, SnarkError::VerifierError(_)),
        "expected verifier rejection, got {error:?}"
    );
    #[cfg(feature = "honest-prover")]
    {
        let error = match result {
            Err(error) | Ok(Err(error)) => error,
            Ok(Ok(())) => panic!("a forged adjacent difference must not verify"),
        };
        ark_piop::errors::assert_soundness_error(error);
    }
}

#[test]
fn bound_difference_honest_ascending_and_descending_verify() {
    run(&[1, 3, 6, 9], &[2, 3, 3, -8], None, true, true).unwrap();
    run(&[9, 6, 3, 1], &[3, 3, 2, -8], None, false, true).unwrap();
}

#[test]
fn bound_difference_two_key_mixed_direction_verifies() {
    // The second key may increase when the first key changes: its comparison
    // is required only within equal first-key prefixes.
    run_two_key_staged(&[1, 1, 2, 2], &[9, 7, 8, 5], &[2, -1, 3, -4])
        .expect("honest mixed-direction witnesses must reach verification")
        .unwrap();
}

#[test]
fn bound_difference_rejects_forged_second_key_under_equal_prefix() {
    // The first pair has equal first keys, so DESC must compare 7 against 9.
    // Only that pair's difference is forged: +2 instead of the actual -2.
    rejects_at_verifier(run_two_key_staged(
        &[1, 1, 2, 2],
        &[7, 9, 8, 5],
        &[2, 1, 3, -2],
    ));
}

#[test]
fn bound_difference_rejects_hidden_duplicate() {
    rejects_at_verifier(run_staged(&[1, 1, 3, 4], &[1, 2, 1, -3], None, true, true));
}

#[test]
fn bound_difference_rejects_hidden_inversion() {
    rejects_at_verifier(run_staged(&[1, 3, 2, 4], &[2, 1, 2, -3], None, true, false));
}

#[test]
fn bound_difference_rejects_wrong_descending_orientation() {
    rejects_at_verifier(run_staged(
        &[4, 2, 3, 1],
        &[2, 1, 2, -3],
        None,
        false,
        false,
    ));
}

#[test]
fn bound_difference_allows_equal_keys_for_nonstrict_sort() {
    run(&[1, 1, 3, 4], &[0, 2, 1, -3], None, true, false).unwrap();
}

#[test]
fn bound_difference_ignores_padding_and_single_active_row() {
    // Only the first adjacent pair is active. Padding payloads/hints need
    // not satisfy subtraction or order; contiguity is an outer prerequisite.
    run(
        &[1, 3, 99, -100],
        &[2, 17, 42, 88],
        Some(&[1, 1, 0, 0]),
        true,
        true,
    )
    .unwrap();
    run(
        &[3, -100, 99, 0],
        &[17, 42, 88, 1],
        Some(&[1, 0, 0, 0]),
        true,
        true,
    )
    .unwrap();
}

#[test]
fn bound_difference_signed_range_uses_an_extra_sign_bit() {
    // 255 is a legal nonnegative difference between signed 8-bit values.
    run(&[-128, 127], &[255, -255], None, true, true).unwrap();
}

#[test]
fn bound_difference_rejects_unproved_comparison_types() {
    for data_type in [
        DataType::Boolean,
        DataType::Utf8,
        DataType::Utf8View,
        DataType::Binary,
        DataType::Float32,
        DataType::Float64,
        DataType::Decimal128(3, 2),
        DataType::Decimal128(38, 0),
    ] {
        assert!(
            checked_difference_type::<B>(&data_type).is_err(),
            "{data_type}"
        );
    }
}

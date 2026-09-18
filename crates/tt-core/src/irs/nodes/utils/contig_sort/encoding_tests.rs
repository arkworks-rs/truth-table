//! Exercise real Arrow difference hints and field encoders before running the
//! composite gadget. In particular, negative masked Decimal128 hints must not
//! be replaced with synthetic signed field values by the test fixture.

use std::sync::Arc;

use arithmetic::{ACTIVATOR_FIELD, encoding::encode_arrow_array_to_field};
use ark_piop::{DefaultSnarkBackend, SnarkBackend, errors::SnarkError};
use datafusion::arrow::{
    array::{
        ArrayRef, BooleanArray, Date32Array, Decimal128Array, Int8Array, Int64Array, UInt64Array,
    },
    compute::concat,
    datatypes::{DataType, Field, Schema},
};

use super::{
    DIFF_INPUT_LABEL, GadgetNode, PerColumnConfig, ROTATED_INPUT_LABEL, SortConfig, TABLE_LABEL,
    TIE_INDICATOR_LABEL, UniformConfig, hints::materialize_diff_array,
};
use crate::{
    irs::nodes::Node,
    test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline_to_verifier},
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

fn encoded_table(columns: &[(&str, ArrayRef)], nullable: bool, active: bool) -> TableSpec<F> {
    let len = columns[0].1.len();
    assert!(len.is_power_of_two());
    let cols = columns
        .iter()
        .map(|(name, array)| {
            assert_eq!(array.len(), len);
            assert_eq!(array.null_count(), 0);
            let segments = encode_arrow_array_to_field::<F>(array).unwrap();
            assert_eq!(segments.len(), 1);
            (
                Arc::new(Field::new(*name, array.data_type().clone(), nullable)),
                segments[0].iter_values().collect(),
            )
        })
        .collect::<Vec<_>>();
    let mut fields = cols
        .iter()
        .map(|(field, _)| field.clone())
        .collect::<Vec<_>>();
    if active {
        fields.push(ACTIVATOR_FIELD.clone());
    }
    TableSpec {
        schema: Schema::new(fields),
        log_size: len.ilog2() as usize,
        cols,
        activator: active.then(|| vec![F::from(1u64); len]),
    }
}

fn rotated(array: &ArrayRef) -> ArrayRef {
    assert!(array.len() >= 2);
    let tail = array.slice(1, array.len() - 1);
    let head = array.slice(0, 1);
    concat(&[tail.as_ref(), head.as_ref()]).unwrap()
}

fn difference(input: &ArrayRef, next: &ArrayRef, asc: bool) -> ArrayRef {
    let (left, right) = if asc { (next, input) } else { (input, next) };
    materialize_diff_array(input.data_type(), left.as_ref(), right.as_ref()).unwrap()
}

fn run_encoded(
    config: SortConfig,
    input: &[(&str, ArrayRef)],
    next: &[(&str, ArrayRef)],
    differences: &[(&str, ArrayRef)],
    ties: &[(&str, ArrayRef)],
) -> Result<Result<(), SnarkError>, SnarkError> {
    // Wide Sign checks use a 2^16-entry range table even for two input rows.
    let srs_nv = if input
        .iter()
        .all(|(_, array)| matches!(array.data_type(), DataType::Int8 | DataType::UInt8))
    {
        8
    } else {
        16
    };
    let node = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(config))));
    let id = node.id();
    let harness = GadgetHarness::<B>::builder(srs_nv)
        .with_gadget(node)
        .with_table(id, TABLE_LABEL, encoded_table(input, false, true))
        .with_table(id, ROTATED_INPUT_LABEL, encoded_table(next, false, true))
        // Production difference hints have nullable metadata. The supported
        // source-type guard must not confuse them with nullable input keys.
        .with_table(
            id,
            DIFF_INPUT_LABEL,
            encoded_table(differences, true, false),
        )
        .with_table(id, TIE_INDICATOR_LABEL, encoded_table(ties, false, false))
        .build();
    run_gadget_pipeline_to_verifier(harness)
}

fn run_single(
    input: ArrayRef,
    asc: bool,
    supplied_difference: Option<ArrayRef>,
) -> Result<Result<(), SnarkError>, SnarkError> {
    let next = rotated(&input);
    let difference = supplied_difference.unwrap_or_else(|| difference(&input, &next, asc));
    let mut mask = vec![true; input.len()];
    *mask.last_mut().unwrap() = false;
    run_encoded(
        SortConfig::Uniform(UniformConfig { asc, strict: true }),
        &[("key", input)],
        &[("key", next)],
        &[("key", difference)],
        &[("tie_0", Arc::new(BooleanArray::from(mask)))],
    )
}

fn accepts(result: Result<Result<(), SnarkError>, SnarkError>) {
    result
        .expect("honest encoded hints must reach verification")
        .expect("honest encoded hints must verify");
}

#[test]
fn bound_difference_real_encoding_signed_int8() {
    accepts(run_single(
        Arc::new(Int8Array::from(vec![-3, -1, 1, 3])),
        true,
        None,
    ));
}

#[test]
fn bound_difference_real_encoding_int64_extremes_both_directions() {
    accepts(run_single(
        Arc::new(Int64Array::from(vec![i64::MIN, i64::MAX])),
        true,
        None,
    ));
    accepts(run_single(
        Arc::new(Int64Array::from(vec![i64::MAX, i64::MIN])),
        false,
        None,
    ));
}

#[test]
fn bound_difference_real_encoding_uint64_extremes() {
    accepts(run_single(
        Arc::new(UInt64Array::from(vec![0, u64::MAX])),
        true,
        None,
    ));
}

#[test]
fn bound_difference_real_encoding_date32_extremes() {
    accepts(run_single(
        Arc::new(Date32Array::from(vec![i32::MIN, i32::MAX])),
        true,
        None,
    ));
}

#[test]
fn bound_difference_real_encoding_mixed_keys_masks_negative_differences() {
    let first: ArrayRef = Arc::new(Int8Array::from(vec![1, 1, 2, 2]));
    let second: ArrayRef = Arc::new(Int8Array::from(vec![3, 1, 9, 7]));
    let first_next = rotated(&first);
    let second_next = rotated(&second);
    let first_difference = difference(&first, &first_next, true);
    let second_difference = difference(&second, &second_next, false);
    // The second key increases at the first-key boundary. Its negative
    // difference is legitimate and must be excluded by the prefix-tie mask.
    assert_eq!(
        second_difference
            .as_any()
            .downcast_ref::<Decimal128Array>()
            .unwrap()
            .value(1),
        -8
    );
    accepts(run_encoded(
        SortConfig::PerColumn(PerColumnConfig {
            sort_specs: vec![
                ("first".into(), true, false),
                ("second".into(), false, false),
            ],
            strict: true,
        }),
        &[("first", first), ("second", second)],
        &[("first", first_next), ("second", second_next)],
        &[("first", first_difference), ("second", second_difference)],
        &[
            (
                "tie_0",
                Arc::new(BooleanArray::from(vec![true, true, true, false])),
            ),
            (
                "tie_1",
                Arc::new(BooleanArray::from(vec![true, false, true, false])),
            ),
        ],
    ));
}

#[test]
fn bound_difference_real_encoding_rejects_forged_arrow_difference() {
    let input: ArrayRef = Arc::new(Int8Array::from(vec![1, 3, 2, 4]));
    let actual = difference(&input, &rotated(&input), true);
    let actual = actual.as_any().downcast_ref::<Decimal128Array>().unwrap();
    assert_eq!(actual.value(1), -1);
    // Change only the inversion's difference before the real Arrow encoder
    // commits it. The negative cyclic-wrap value retains its real encoding.
    let forged = actual
        .values()
        .iter()
        .enumerate()
        .map(|(index, &value)| if index == 1 { 1 } else { value })
        .collect::<Vec<_>>();
    let forged = Decimal128Array::from(forged)
        .with_precision_and_scale(actual.precision(), actual.scale())
        .unwrap();
    let result = run_single(input, true, Some(Arc::new(forged)));
    #[cfg(not(feature = "honest-prover"))]
    {
        let error = result
            .expect("forged encoded hints must reach verification")
            .expect_err("forged encoded hints must fail verification");
        assert!(matches!(error, SnarkError::VerifierError(_)), "{error:?}");
    }
    #[cfg(feature = "honest-prover")]
    {
        let error = match result {
            Err(error) | Ok(Err(error)) => error,
            Ok(Ok(())) => panic!("forged encoded hints must not verify"),
        };
        ark_piop::errors::assert_soundness_error(error);
    }
}

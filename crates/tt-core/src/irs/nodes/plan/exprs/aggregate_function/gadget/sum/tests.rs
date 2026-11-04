//! An ungrouped SUM over four Int64 rows, through the SUM gadget and its
//! keyed sumcheck: one constant key on each side, one active output row.

use std::sync::Arc;

use arithmetic::ACTIVATOR_FIELD;
use ark_ff::Field as _;
use ark_piop::{DefaultSnarkBackend, SnarkBackend, errors::SnarkError};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{CHECKED_OUTPUT_LABEL, GadgetNode, ensure_fits_field};
use crate::irs::nodes::Node;
use crate::irs::nodes::plan::exprs::aggregate_function::gadget::{
    INPUT_RLC_LABEL, OUTPUT_LABEL, OUTPUT_RLC_LABEL, input_label,
};
use crate::irs::nodes::utils::contig_sort::tests::assert_rejected;
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

fn table(name: &str, values: Vec<F>, activator: Vec<F>) -> TableSpec<F> {
    let field = Arc::new(Field::new(name, DataType::Int64, false));
    TableSpec {
        schema: Schema::new(vec![
            field.as_ref().clone(),
            ACTIVATOR_FIELD.as_ref().clone(),
        ]),
        log_size: 2,
        cols: vec![(field, values)],
        activator: Some(activator),
    }
}

/// Proves that `sum` is the SUM of `inputs`, both as field elements; an
/// Int64 SUM has no room for its rows, so its output is checked.
fn run(inputs: [F; 4], sum: F) -> Result<(), SnarkError> {
    let gadget = Arc::new(Node::<B>::Gadget(Arc::new(GadgetNode::<B>::new())));
    let id = gadget.id();
    let all = vec![F::from(1u64); 4];
    let first = vec![F::from(1u64), F::from(0u64), F::from(0u64), F::from(0u64)];
    let output = vec![sum, F::from(0u64), F::from(0u64), F::from(0u64)];
    run_gadget_pipeline(
        GadgetHarness::<B>::builder(16)
            .with_gadget(gadget)
            .with_table(
                id,
                &input_label(0),
                table("x", inputs.to_vec(), all.clone()),
            )
            .with_table(id, INPUT_RLC_LABEL, table("key", all.clone(), all))
            .with_table(id, OUTPUT_LABEL, table("s", output.clone(), first.clone()))
            .with_table(id, CHECKED_OUTPUT_LABEL, table("s", output, first.clone()))
            .with_table(id, OUTPUT_RLC_LABEL, table("key", first.clone(), first))
            .build(),
    )
}

fn int(v: i64) -> F {
    F::from(v)
}

#[test]
fn a_sum_within_its_type_verifies() {
    run([int(1), int(-2), int(30), int(4)], int(33)).expect("a sum within Int64 verifies");
}

#[test]
fn a_sum_past_its_type_is_rejected() {
    // Each 2^62 fits Int64; the exact sum, 2^64, does not, though the keyed
    // sumcheck holds.
    let quarter = F::from(2u64).pow([62]);
    assert_rejected(run([quarter; 4], F::from(2u64).pow([64])));
}

#[test]
fn a_sum_that_could_leave_the_field_is_refused() {
    let wide = DataType::Decimal128(38, 2);
    ensure_fits_field::<B>(&wide, 23).expect("2^23 rows of Decimal128(38) fit");
    assert!(ensure_fits_field::<B>(&wide, 125).is_err());
}

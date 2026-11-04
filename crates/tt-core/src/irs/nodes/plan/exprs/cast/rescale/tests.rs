//! A cast's output check through the rescale gadget on four-row columns: the
//! output column is what the prover claims the cast produced.

use std::sync::Arc;

use arithmetic::ACTIVATOR_FIELD;
use ark_ff::Field as _;
use ark_piop::{DefaultSnarkBackend, SnarkBackend, errors::SnarkError};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{INPUT_LABEL, OUTPUT_LABEL, RescaleNode};
use crate::irs::nodes::Node;
use crate::irs::nodes::utils::contig_sort::tests::assert_rejected;
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

fn table(data_type: DataType, values: [F; 4]) -> TableSpec<F> {
    let field = Arc::new(Field::new("v", data_type, false));
    TableSpec {
        schema: Schema::new(vec![
            field.as_ref().clone(),
            ACTIVATOR_FIELD.as_ref().clone(),
        ]),
        log_size: 2,
        cols: vec![(field, values.to_vec())],
        activator: Some(vec![F::from(1u64); 4]),
    }
}

fn run(input: (DataType, [F; 4]), output: (DataType, [F; 4])) -> Result<(), SnarkError> {
    let gadget = Arc::new(Node::<B>::Gadget(Arc::new(RescaleNode::<B>::new())));
    let id = gadget.id();
    run_gadget_pipeline(
        GadgetHarness::<B>::builder(16)
            .with_gadget(gadget)
            .with_table(id, INPUT_LABEL, table(input.0, input.1))
            .with_table(id, OUTPUT_LABEL, table(output.0, output.1))
            .build(),
    )
}

fn int(v: i64) -> F {
    F::from(v)
}

#[test]
fn a_narrowing_cast_keeps_its_type() {
    let values = [int(-128), int(127), int(0), int(5)];
    run((DataType::Int64, values), (DataType::Int8, values)).expect("values that fit Int8 verify");
    let values = [int(1000), int(127), int(0), int(5)];
    assert_rejected(run((DataType::Int64, values), (DataType::Int8, values)));
}

#[test]
fn a_scale_up_keeps_its_type() {
    let ten = |exp: u64| F::from(10u64).pow([exp]);
    let (from, to) = (DataType::Decimal128(38, 0), DataType::Decimal128(38, 2));
    run(
        (from.clone(), [ten(30), int(1), int(0), int(-7)]),
        (to.clone(), [ten(32), int(100), int(0), int(-700)]),
    )
    .expect("a scale-up within Decimal128(38) verifies");
    // 10^37 · 10^2 is past even the [-2^127, 2^127) range checked.
    assert_rejected(run(
        (from, [ten(37), int(1), int(0), int(-7)]),
        (to, [ten(39), int(100), int(0), int(-700)]),
    ));
}

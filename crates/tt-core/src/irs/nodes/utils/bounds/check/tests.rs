//! The type range check on a four-row column, through a gadget that calls it
//! inline.

use std::sync::{Arc, Mutex};

use arithmetic::ACTIVATOR_FIELD;
use ark_ff::Field as _;
use ark_piop::{DefaultSnarkBackend, SnarkBackend, errors::SnarkError};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use crate::irs::nodes::utils::contig_sort::tests::assert_rejected;
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};
use crate::test_utils::inline_gadget::InlineGadget;

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const LABEL: &str = "__input__";

fn int(v: i128) -> F {
    F::from(v)
}

fn pow2(bits: u32) -> F {
    F::from(2u64).pow([bits as u64])
}

/// The verifier's result, and whether `honest_check` accepted the column.
fn run(
    data_type: DataType,
    values: Vec<F>,
    activator: Vec<i128>,
) -> (Result<(), SnarkError>, bool) {
    let honest = Arc::new(Mutex::new(false));
    let honest_in_prover = honest.clone();
    let gadget = InlineGadget::<B>::node(
        Box::new(move |prover, payload| {
            let table = &payload[LABEL];
            let col = table.tracked_col_by_ind(table.data_tracked_polys_indices()[0]);
            let data_type = col.field_ref().expect("a typed column").data_type().clone();
            let activator = table.activator_tracked_poly();
            let value = col.data_tracked_poly();
            *honest_in_prover.lock().unwrap() =
                super::honest_check(activator.as_ref(), &value, &data_type, "test").is_ok();
            super::prove(prover, activator.as_ref(), &value, &data_type)
        }),
        Box::new(move |verifier, payload| {
            let table = &payload[LABEL];
            let col = table.tracked_col_oracle_by_ind(table.data_tracked_oracles_indices()[0]);
            let data_type = col.field_ref().expect("a typed column").data_type().clone();
            let activator = table.activator_tracked_poly();
            super::verify(
                verifier,
                activator.as_ref(),
                &col.data_tracked_oracle(),
                &data_type,
            )
        }),
    );
    let id = gadget.id();
    let field = Arc::new(Field::new("v", data_type, false));
    let spec = TableSpec {
        schema: Schema::new(vec![
            field.as_ref().clone(),
            ACTIVATOR_FIELD.as_ref().clone(),
        ]),
        log_size: 2,
        cols: vec![(field, values)],
        activator: Some(activator.into_iter().map(int).collect()),
    };
    let result = run_gadget_pipeline(
        GadgetHarness::<B>::builder(16)
            .with_gadget(gadget)
            .with_table(id, LABEL, spec)
            .build(),
    );
    let honest = *honest.lock().unwrap();
    (result, honest)
}

fn accepted(data_type: DataType, values: [F; 4]) {
    let (result, honest) = run(data_type.clone(), values.to_vec(), vec![1; 4]);
    result.unwrap_or_else(|e| panic!("{data_type} values in range verify: {e:?}"));
    assert!(honest, "honest_check accepts {data_type} values in range");
}

fn rejected(data_type: DataType, values: [F; 4]) {
    let (result, honest) = run(data_type.clone(), values.to_vec(), vec![1; 4]);
    assert!(
        !honest,
        "honest_check rejects {data_type} values out of range"
    );
    assert_rejected(result);
}

#[test]
fn unsigned_bounds() {
    accepted(DataType::UInt8, [int(0), int(255), int(1), int(2)]);
    rejected(DataType::UInt8, [int(0), int(256), int(1), int(2)]);
    rejected(DataType::UInt8, [int(0), int(-1), int(1), int(2)]);
    let top = pow2(64) - int(1);
    accepted(DataType::UInt64, [int(0), top, int(1), int(2)]);
    rejected(DataType::UInt64, [int(0), pow2(64), int(1), int(2)]);
}

#[test]
fn signed_bounds() {
    accepted(DataType::Int8, [int(-128), int(127), int(0), int(-1)]);
    rejected(DataType::Int8, [int(128), int(0), int(0), int(0)]);
    rejected(DataType::Int8, [int(-129), int(0), int(0), int(0)]);
    let (min, max) = (int(i64::MIN.into()), int(i64::MAX.into()));
    accepted(DataType::Int64, [min, max, int(0), int(-1)]);
    rejected(DataType::Int64, [max + int(1), int(0), int(0), int(0)]);
    rejected(DataType::Int64, [min - int(1), int(0), int(0), int(0)]);
}

#[test]
fn decimal_bounds() {
    // 10^5 needs 17 bits, so Decimal128(5, 2) admits [-2^17, 2^17).
    let decimal = DataType::Decimal128(5, 2);
    let edge = pow2(17);
    accepted(
        decimal.clone(),
        [edge - int(1), -edge, int(99_999), int(-99_999)],
    );
    rejected(decimal.clone(), [edge, int(0), int(0), int(0)]);
    rejected(decimal, [-edge - int(1), int(0), int(0), int(0)]);
}

#[test]
fn inactive_rows_are_not_checked() {
    let (result, honest) = run(
        DataType::Int8,
        vec![int(3), int(1000), int(-5), pow2(100)],
        vec![1, 0, 1, 0],
    );
    result.expect("inactive rows are masked out");
    assert!(honest);
}

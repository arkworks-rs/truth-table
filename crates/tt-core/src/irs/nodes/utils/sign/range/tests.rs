//! The range check on a four-row column, through a gadget that calls it
//! inline.

use std::sync::Arc;

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

/// Range-checks `values` (rows with activator 0 excluded) at `width`.
fn run(values: Vec<F>, activator: Vec<F>, width: usize) -> Result<(), SnarkError> {
    let gadget = InlineGadget::<B>::node(
        Box::new(move |prover, payload| {
            let table = &payload[LABEL];
            let col = table.tracked_col_by_ind(table.data_tracked_polys_indices()[0]);
            super::prove(prover, &col, width)
        }),
        Box::new(move |verifier, payload| {
            let table = &payload[LABEL];
            let col = table.tracked_col_oracle_by_ind(table.data_tracked_oracles_indices()[0]);
            super::verify(verifier, &col, width)
        }),
    );
    let id = gadget.id();
    let field = Arc::new(Field::new("d", DataType::UInt64, false));
    let spec = TableSpec {
        schema: Schema::new(vec![
            field.as_ref().clone(),
            ACTIVATOR_FIELD.as_ref().clone(),
        ]),
        log_size: 2,
        cols: vec![(field, values)],
        activator: Some(activator),
    };
    run_gadget_pipeline(
        GadgetHarness::<B>::builder(16)
            .with_gadget(gadget)
            .with_table(id, LABEL, spec)
            .build(),
    )
}

fn all_active() -> Vec<F> {
    vec![F::from(1u64); 4]
}

fn pow2(bits: u32) -> F {
    F::from(2u64).pow([bits as u64])
}

#[test]
fn narrow_boundaries_accepted() {
    let values = vec![
        F::from(0u64),
        F::from(1u64),
        F::from(254u64),
        F::from(255u64),
    ];
    run(values, all_active(), 8).expect("values in [0, 2^8) verify");
}

#[test]
fn narrow_overflow_rejected() {
    let values = vec![F::from(0u64), F::from(256u64), F::from(3u64), F::from(4u64)];
    assert_rejected(run(values, all_active(), 8));
}

#[test]
fn sixteen_bit_boundaries() {
    let top = F::from(u64::from(u16::MAX));
    run(
        vec![top, F::from(0u64), top, F::from(7u64)],
        all_active(),
        16,
    )
    .expect("2^16 - 1 verifies at width 16");
    assert_rejected(run(
        vec![top + F::from(1u64), F::from(0u64), top, F::from(7u64)],
        all_active(),
        16,
    ));
}

#[test]
fn wide_boundaries_accepted() {
    for width in [17u32, 32, 40, 64] {
        let top = pow2(width) - F::from(1u64);
        let values = vec![top, F::from(0u64), pow2(width - 1), F::from(65_536u64)];
        run(values, all_active(), width as usize)
            .unwrap_or_else(|e| panic!("values in [0, 2^{width}) verify: {e:?}"));
    }
}

#[test]
fn wide_overflow_rejected() {
    for width in [17u32, 40] {
        let values = vec![F::from(0u64), pow2(width), F::from(5u64), F::from(6u64)];
        assert_rejected(run(values, all_active(), width as usize));
    }
}

#[test]
fn negative_value_rejected() {
    for width in [8usize, 40] {
        let values = vec![F::from(0u64), -F::from(1u64), F::from(5u64), F::from(6u64)];
        assert_rejected(run(values, all_active(), width));
    }
}

#[test]
fn inactive_rows_are_not_checked() {
    let activator = vec![F::from(1u64), F::from(0u64), F::from(1u64), F::from(0u64)];
    for width in [8usize, 40] {
        let values = vec![F::from(3u64), -F::from(1u64), F::from(5u64), pow2(60)];
        run(values, activator.clone(), width).expect("inactive rows are masked out");
    }
}

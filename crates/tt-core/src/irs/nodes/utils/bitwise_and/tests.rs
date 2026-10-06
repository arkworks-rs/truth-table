//! Tests for the `BitwiseAnd` gadget node (paper §6.3, PIOP 9).

use std::sync::Arc;

use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{GadgetNode, INPUT_LABEL};
use crate::irs::nodes::Node;
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const BIT_WIDTH: usize = 2;

fn field(name: &str) -> Arc<Field> {
    Arc::new(Field::new(name, DataType::UInt64, false))
}

fn f(vals: &[u64]) -> Vec<F> {
    vals.iter().map(|&v| F::from(v)).collect()
}

/// Run prove + verify on `(c1, c2, c3)` with an optional activator.
fn run(
    c1: Vec<F>,
    c2: Vec<F>,
    c3: Vec<F>,
    activator: Option<Vec<F>>,
) -> Result<(), ark_piop::errors::SnarkError> {
    let log_size = c1.len().ilog2() as usize;
    let gadget: Arc<Node<B>> = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(BIT_WIDTH))));
    let gadget_id = gadget.id();

    let c1_field = field("c1");
    let c2_field = field("c2");
    let c3_field = field("c3");
    let schema = Schema::new(vec![
        c1_field.as_ref().clone(),
        c2_field.as_ref().clone(),
        c3_field.as_ref().clone(),
    ]);

    let harness = GadgetHarness::<B>::builder(6)
        .with_gadget(gadget)
        .with_table(
            gadget_id,
            INPUT_LABEL,
            TableSpec {
                schema,
                log_size,
                cols: vec![(c1_field, c1), (c2_field, c2), (c3_field, c3)],
                activator,
            },
        )
        .build();

    run_gadget_pipeline(harness)
}

#[test]
fn correct_and_passes() {
    // 3&1=1, 2&3=2, 1&2=0, 0&2=0
    run(f(&[3, 2, 1, 0]), f(&[1, 3, 2, 2]), f(&[1, 2, 0, 0]), None)
        .expect("honest bitwise AND should verify");
}

#[test]
fn wrong_and_row_fails() {
    // Row 2 claims 1&2=1 (should be 0).
    let result = run(f(&[3, 2, 1, 0]), f(&[1, 3, 2, 2]), f(&[1, 2, 1, 0]), None);
    assert!(result.is_err(), "wrong AND row must not verify");
}

#[test]
fn inactive_rows_are_exempt() {
    // Row 2 is wrong (1&2=3) but deactivated; row 3 wrong and deactivated
    // too. Active rows 0 and 1 are correct.
    run(
        f(&[3, 2, 1, 0]),
        f(&[1, 3, 2, 2]),
        f(&[1, 2, 3, 1]),
        Some(f(&[1, 1, 0, 0])),
    )
    .expect("deactivated rows must be exempt from the AND check");
}

#[test]
fn active_wrong_row_fails_with_activator() {
    // Same activator as above but the *active* row 1 is wrong (2&3=3).
    let result = run(
        f(&[3, 2, 1, 0]),
        f(&[1, 3, 2, 2]),
        f(&[1, 3, 3, 1]),
        Some(f(&[1, 1, 0, 0])),
    );
    assert!(result.is_err(), "active wrong row must not verify");
}

/// Run prove + verify in constant mode: `c3 = c1 ∧ constant`.
fn run_const(
    constant: u64,
    c1: Vec<F>,
    c3: Vec<F>,
    activator: Option<Vec<F>>,
) -> Result<(), ark_piop::errors::SnarkError> {
    let log_size = c1.len().ilog2() as usize;
    let gadget: Arc<Node<B>> = Arc::new(Node::Gadget(Arc::new(
        GadgetNode::<B>::new_with_constant(BIT_WIDTH, constant),
    )));
    let gadget_id = gadget.id();

    let c1_field = field("c1");
    let c3_field = field("c3");
    let schema = Schema::new(vec![c1_field.as_ref().clone(), c3_field.as_ref().clone()]);

    let harness = GadgetHarness::<B>::builder(6)
        .with_gadget(gadget)
        .with_table(
            gadget_id,
            INPUT_LABEL,
            TableSpec {
                schema,
                log_size,
                cols: vec![(c1_field, c1), (c3_field, c3)],
                activator,
            },
        )
        .build();

    run_gadget_pipeline(harness)
}

#[test]
fn constant_operand_passes() {
    // φ = 2: 3&2=2, 2&2=2, 1&2=0, 0&2=0
    run_const(2, f(&[3, 2, 1, 0]), f(&[2, 2, 0, 0]), None)
        .expect("honest constant-operand AND should verify");
}

#[test]
fn constant_operand_wrong_row_fails() {
    // Row 2 claims 1&2=2 (should be 0).
    let result = run_const(2, f(&[3, 2, 1, 0]), f(&[2, 2, 2, 0]), None);
    assert!(
        result.is_err(),
        "wrong constant-operand AND must not verify"
    );
}

#[test]
fn constant_operand_inactive_rows_exempt() {
    // Rows 2 and 3 wrong but deactivated.
    run_const(
        2,
        f(&[3, 2, 1, 0]),
        f(&[2, 2, 3, 1]),
        Some(f(&[1, 1, 0, 0])),
    )
    .expect("deactivated rows must be exempt in constant mode");
}

#[test]
fn out_of_range_operand_fails() {
    // Row 0: c1 = 5 is not a 2-bit value, even though 5&1=1 holds
    // bit-wise; both the range check and the AND-table lookup reject it.
    let result = run(f(&[5, 2, 1, 0]), f(&[1, 3, 2, 2]), f(&[1, 2, 0, 0]), None);
    assert!(result.is_err(), "out-of-range operand must not verify");
}

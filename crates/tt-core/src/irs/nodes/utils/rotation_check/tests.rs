//! Tests for `RotationCheck` composite gadget node.
//!
//! Small tables of `log_size = 2` (n = 4). Semantics under test:
//!   Direction::Right, shift s:  right[i] = left[(i - s) mod n]
//!   Direction::Left,  shift s:  right[i] = left[(i + s) mod n]

use std::sync::Arc;

use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{Direction, GadgetNode, LEFT_LABEL, RIGHT_LABEL};
use crate::irs::nodes::Node;
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const NV: usize = 2; // n = 4

fn build_gadget(shift: usize, direction: Direction) -> Arc<Node<B>> {
    Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(
        shift, direction,
    ))))
}

fn u64_field(name: &str) -> Arc<Field> {
    Arc::new(Field::new(name, DataType::UInt64, false))
}

/// Rotate `xs` right by `shift`: result[i] = xs[(i - shift) mod n].
fn rotate_right(xs: &[F], shift: usize) -> Vec<F> {
    let n = xs.len();
    (0..n).map(|i| xs[(i + n - (shift % n)) % n]).collect()
}

/// Rotate `xs` left by `shift`: result[i] = xs[(i + shift) mod n].
fn rotate_left(xs: &[F], shift: usize) -> Vec<F> {
    let n = xs.len();
    (0..n).map(|i| xs[(i + (shift % n)) % n]).collect()
}

fn run(
    shift: usize,
    direction: Direction,
    left_evals: Vec<F>,
    right_evals: Vec<F>,
) -> Result<(), ark_piop::errors::SnarkError> {
    let gadget = build_gadget(shift, direction);
    let gadget_id = gadget.id();

    let left_f = u64_field("data");
    let right_f = u64_field("data");
    let left_schema = Schema::new(vec![left_f.as_ref().clone()]);
    let right_schema = Schema::new(vec![right_f.as_ref().clone()]);

    let harness = GadgetHarness::<B>::builder(6)
        .with_gadget(gadget)
        .with_table(
            gadget_id,
            LEFT_LABEL,
            TableSpec {
                schema: left_schema,
                log_size: NV,
                cols: vec![(left_f, left_evals)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            RIGHT_LABEL,
            TableSpec {
                schema: right_schema,
                log_size: NV,
                cols: vec![(right_f, right_evals)],
                activator: None,
            },
        )
        .build();

    run_gadget_pipeline(harness)
}

// ---- Positive cases ----

#[test]
fn identity_rotation_zero() {
    let left: Vec<F> = (0..4).map(|i| F::from(10u64 + i)).collect();
    let right = left.clone();
    run(0, Direction::Right, left, right).expect("zero shift is identity");
}

#[test]
fn right_shift_by_one() {
    let left: Vec<F> = vec![
        F::from(10u64),
        F::from(20u64),
        F::from(30u64),
        F::from(40u64),
    ];
    // right[i] = left[(i - 1) mod 4] = [40, 10, 20, 30]
    let right = rotate_right(&left, 1);
    assert_eq!(
        right,
        vec![
            F::from(40u64),
            F::from(10u64),
            F::from(20u64),
            F::from(30u64)
        ]
    );
    run(1, Direction::Right, left, right).expect("right-shift by 1 should verify");
}

#[test]
fn right_shift_by_two() {
    let left: Vec<F> = vec![F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];
    let right = rotate_right(&left, 2);
    run(2, Direction::Right, left, right).expect("right-shift by 2 should verify");
}

#[test]
fn left_shift_by_one() {
    let left: Vec<F> = vec![
        F::from(10u64),
        F::from(20u64),
        F::from(30u64),
        F::from(40u64),
    ];
    // right[i] = left[(i + 1) mod 4] = [20, 30, 40, 10]
    let right = rotate_left(&left, 1);
    assert_eq!(
        right,
        vec![
            F::from(20u64),
            F::from(30u64),
            F::from(40u64),
            F::from(10u64)
        ]
    );
    run(1, Direction::Left, left, right).expect("left-shift by 1 should verify");
}

#[test]
fn left_shift_by_three_equals_right_shift_by_one() {
    let left: Vec<F> = vec![
        F::from(10u64),
        F::from(20u64),
        F::from(30u64),
        F::from(40u64),
    ];
    let right = rotate_left(&left, 3);
    // Rotating left by 3 == rotating right by 1 on a 4-row table.
    assert_eq!(right, rotate_right(&left, 1));
    run(3, Direction::Left, left, right).expect("left-shift by 3 should verify");
}

// ---- Adversarial cases ----

#[test]
fn wrong_direction_rejected() {
    // left rotated LEFT by 1, but the gadget is configured as RIGHT by 1.
    let left: Vec<F> = vec![
        F::from(10u64),
        F::from(20u64),
        F::from(30u64),
        F::from(40u64),
    ];
    let right = rotate_left(&left, 1);
    assert!(
        run(1, Direction::Right, left, right).is_err(),
        "left-rotated table must not verify as right rotation"
    );
}

#[test]
fn wrong_shift_amount_rejected() {
    // left rotated right by 2, but the gadget is configured as right by 1.
    let left: Vec<F> = vec![
        F::from(10u64),
        F::from(20u64),
        F::from(30u64),
        F::from(40u64),
    ];
    let right = rotate_right(&left, 2);
    assert!(
        run(1, Direction::Right, left, right).is_err(),
        "wrong shift amount must not verify"
    );
}

#[test]
fn arbitrary_permutation_rejected() {
    // right is a permutation of left but not a cyclic rotation.
    let left: Vec<F> = vec![
        F::from(10u64),
        F::from(20u64),
        F::from(30u64),
        F::from(40u64),
    ];
    let right = vec![
        F::from(20u64),
        F::from(10u64),
        F::from(40u64),
        F::from(30u64),
    ];
    assert!(
        run(1, Direction::Right, left, right).is_err(),
        "non-rotation permutation must not verify"
    );
}

#[test]
fn tampered_single_value_rejected() {
    let left: Vec<F> = vec![
        F::from(10u64),
        F::from(20u64),
        F::from(30u64),
        F::from(40u64),
    ];
    let mut right = rotate_right(&left, 1);
    right[0] = F::from(999u64); // wrong at one row
    assert!(
        run(1, Direction::Right, left, right).is_err(),
        "single tampered value must not verify"
    );
}

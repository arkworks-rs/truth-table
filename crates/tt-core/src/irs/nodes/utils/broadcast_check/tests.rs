//! Tests for `BroadcastCheck` gadget node.

use std::sync::Arc;

use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{CHAR_LABEL, GadgetNode, STR_LABEL};
use crate::irs::nodes::Node;
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const STR_NV: usize = 1;
const CHAR_NV: usize = 2;

fn build_gadget() -> Arc<Node<B>> {
    Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new())))
}

fn fixed_src_evals() -> Vec<F> {
    vec![F::from(0u64), F::from(0u64), F::from(1u64), F::from(1u64)]
}
fn fixed_ind_evals() -> Vec<F> {
    vec![F::from(0u64), F::from(1u64)]
}

fn field(name: &str) -> Arc<Field> {
    Arc::new(Field::new(name, DataType::UInt64, false))
}

/// Run prove + verify with the given string-level `x` and char-level `x'`.
fn run(
    str_x: Vec<F>,
    char_x_prime: Vec<F>,
    char_act: Option<Vec<F>>,
    str_act: Option<Vec<F>>,
) -> Result<(), ark_piop::errors::SnarkError> {
    let gadget = build_gadget();
    let gadget_id = gadget.id();

    let ind_field = field("ind");
    let x_field = field("x");
    let src_field = field("src");
    let x_prime_field = field("x_prime");

    let str_schema = Schema::new(vec![
        ind_field.as_ref().clone(),
        x_field.as_ref().clone(),
    ]);
    let char_schema = Schema::new(vec![
        src_field.as_ref().clone(),
        x_prime_field.as_ref().clone(),
    ]);

    let harness = GadgetHarness::<B>::builder(4)
        .with_gadget(gadget)
        .with_table(
            gadget_id,
            STR_LABEL,
            TableSpec {
                schema: str_schema,
                log_size: STR_NV,
                cols: vec![(ind_field, fixed_ind_evals()), (x_field, str_x)],
                activator: str_act,
            },
        )
        .with_table(
            gadget_id,
            CHAR_LABEL,
            TableSpec {
                schema: char_schema,
                log_size: CHAR_NV,
                cols: vec![
                    (src_field, fixed_src_evals()),
                    (x_prime_field, char_x_prime),
                ],
                activator: char_act,
            },
        )
        .build();

    run_gadget_pipeline(harness)
}

#[test]
fn broadcast_holds_end_to_end() {
    // Strings: x = [10, 20]. Chars: x' = [10, 10, 20, 20] (broadcast of x).
    let str_x = vec![F::from(10u64), F::from(20u64)];
    let char_x_prime = vec![
        F::from(10u64),
        F::from(10u64),
        F::from(20u64),
        F::from(20u64),
    ];
    run(str_x, char_x_prime, None, None).expect("broadcast should verify");
}

#[test]
fn broadcast_holds_with_zero_values() {
    let str_x = vec![F::from(0u64), F::from(0u64)];
    let char_x_prime = vec![F::from(0u64); 4];
    run(str_x, char_x_prime, None, None).expect("zero broadcast should verify");
}

#[test]
fn broadcast_violation_char_value_rejected() {
    let str_x = vec![F::from(10u64), F::from(20u64)];
    let char_x_prime = vec![
        F::from(10u64),
        F::from(10u64),
        F::from(99u64), // wrong
        F::from(20u64),
    ];
    assert!(
        run(str_x, char_x_prime, None, None).is_err(),
        "corrupted broadcast must not verify"
    );
}

#[test]
fn broadcast_violation_swap_within_string_rejected() {
    let str_x = vec![F::from(10u64), F::from(20u64)];
    let char_x_prime = vec![
        F::from(20u64), // wrong (owner is string 0 with value 10)
        F::from(10u64),
        F::from(10u64), // wrong (owner is string 1 with value 20)
        F::from(20u64),
    ];
    assert!(
        run(str_x, char_x_prime, None, None).is_err(),
        "cross-string swap must not verify"
    );
}

#[test]
fn broadcast_with_activator_end_to_end() {
    // Char 3 is inactive; its value can be garbage and the check should
    // still pass. String side has no activator.
    let str_x = vec![F::from(10u64), F::from(20u64)];
    let char_x_prime = vec![
        F::from(10u64),
        F::from(10u64),
        F::from(20u64),
        F::from(777u64),
    ];
    let char_act = Some(vec![
        F::from(1u64),
        F::from(1u64),
        F::from(1u64),
        F::from(0u64),
    ]);
    run(str_x, char_x_prime, char_act, None).expect("activator-masked broadcast should verify");
}

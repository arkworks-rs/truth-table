//! Tests for `ActivatorConsistencyCheck` gadget node.
//!
//! Uses the [`crate::test_utils::gadget_harness`] harness to build a one-node
//! IR, populate its payload, and drive prove/verify end-to-end.

use std::sync::Arc;

use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use indexmap::IndexMap;

use super::{GadgetNode, LHS_LABEL, RHS_LABEL};
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

fn lhs_field() -> Arc<Field> {
    Arc::new(Field::new("src", DataType::UInt64, false))
}
fn rhs_ind_field() -> Arc<Field> {
    Arc::new(Field::new("ind", DataType::UInt64, false))
}
fn rhs_len_field() -> Arc<Field> {
    Arc::new(Field::new("l", DataType::UInt64, false))
}

/// Runs prove + verify with the given length column and activators. `None`
/// for an activator means "no activator" (all rows active). Returns the
/// verification result.
fn run(
    length_evals: Vec<F>,
    char_act_evals: Option<Vec<F>>,
    str_act_evals: Option<Vec<F>>,
) -> Result<(), ark_piop::errors::SnarkError> {
    let gadget = build_gadget();
    let gadget_id = gadget.id();

    let lhs_schema = Schema::new(vec![lhs_field().as_ref().clone()]);
    let rhs_schema = Schema::new(vec![
        rhs_ind_field().as_ref().clone(),
        rhs_len_field().as_ref().clone(),
    ]);

    let harness = GadgetHarness::<B>::builder(4)
        .with_gadget(gadget)
        .with_table(
            gadget_id,
            LHS_LABEL,
            TableSpec {
                schema: lhs_schema,
                log_size: CHAR_NV,
                cols: vec![(lhs_field(), fixed_src_evals())],
                activator: char_act_evals,
            },
        )
        .with_table(
            gadget_id,
            RHS_LABEL,
            TableSpec {
                schema: rhs_schema,
                log_size: STR_NV,
                cols: vec![
                    (rhs_ind_field(), fixed_ind_evals()),
                    (rhs_len_field(), length_evals),
                ],
                activator: str_act_evals,
            },
        )
        .build();

    run_gadget_pipeline(harness)
}

#[test]
fn consistent_no_activators() {
    // 2 chars per string, all active. length = [2, 2].
    let length = vec![F::from(2u64), F::from(2u64)];
    run(length, None, None).expect("consistent inputs should verify");
}

#[test]
fn consistent_char_activator_deactivates_one() {
    // Deactivate char 3 (owned by string 1). Expected length[1] = 1.
    let length = vec![F::from(2u64), F::from(1u64)];
    let char_act = Some(vec![
        F::from(1u64),
        F::from(1u64),
        F::from(1u64),
        F::from(0u64),
    ]);
    run(length, char_act, None).expect("consistent w/ char activator should verify");
}

#[test]
fn wrong_length_rejected() {
    let length = vec![F::from(2u64), F::from(3u64)];
    assert!(
        run(length, None, None).is_err(),
        "length overstatement must not verify"
    );
}

#[test]
fn understated_length_rejected() {
    let length = vec![F::from(1u64), F::from(2u64)];
    assert!(
        run(length, None, None).is_err(),
        "length understatement must not verify"
    );
}

#[test]
fn inactive_string_ignores_length() {
    // String 1 inactive; its chars also masked off. Length[1] can be garbage.
    let length = vec![F::from(2u64), F::from(999u64)];
    let char_act = Some(vec![
        F::from(1u64),
        F::from(1u64),
        F::from(0u64),
        F::from(0u64),
    ]);
    let str_act = Some(vec![F::from(1u64), F::from(0u64)]);
    run(length, char_act, str_act)
        .expect("inactive string with masked chars should verify regardless of length");
}

#[test]
fn inactive_string_with_active_chars_rejected() {
    // String 1 inactive (RHS mult 0) but chars 2/3 still active (LHS count 2).
    let length = vec![F::from(2u64), F::from(2u64)];
    let str_act = Some(vec![F::from(1u64), F::from(0u64)]);
    assert!(
        run(length, None, str_act).is_err(),
        "inactive string with active chars must not verify"
    );
}

// Silence unused-import lint (Node<B> only surfaces through `build_gadget`).
#[allow(dead_code)]
fn _touch_types<T: SnarkBackend>(_ir: &crate::prover::irs::GadgetReadyIr<T>) {}

// Keep IndexMap import warning-free when the test module doesn't use it directly.
#[allow(dead_code)]
fn _touch_indexmap() -> IndexMap<String, ()> {
    IndexMap::new()
}

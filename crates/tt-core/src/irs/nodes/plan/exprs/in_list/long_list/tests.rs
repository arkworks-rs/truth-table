//! Tests for the long-list membership gadget against a dishonest prover, on
//! hand-built tables of four rows and the list `S = {2, 5, 7}`.
//!
//! The harness skips gadget planning, so each test supplies `û`, its flag and
//! the sort's hint tables itself; a forged one reaches prover and verifier
//! alike, as a committed witness does in a real proof.

use std::sync::Arc;

use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion_common::ScalarValue;

use super::{FLAG_COL, LongListNode, UNION_LABEL};
use crate::irs::nodes::Node;
use crate::irs::nodes::plan::exprs::in_list::gadget::{INPUT_LABEL, OUTPUT_LABEL};
use crate::irs::nodes::utils::contig_sort::tests::{active_rows, assert_rejected};
use crate::irs::nodes::utils::contig_sort::{ACTIVE_ROWS_LABEL, ROTATED_INPUT_LABEL};
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

fn fs(values: &[u64]) -> Vec<F> {
    values.iter().map(|&v| F::from(v)).collect()
}

fn table(cols: &[(&str, DataType, &[u64])], activator: Option<&[u64]>) -> TableSpec<F> {
    let fields: Vec<Arc<Field>> = cols
        .iter()
        .map(|(name, data_type, _)| Arc::new(Field::new(*name, data_type.clone(), false)))
        .collect();
    let mut schema_fields: Vec<Field> = fields.iter().map(|field| field.as_ref().clone()).collect();
    if activator.is_some() {
        schema_fields.push(arithmetic::ACTIVATOR_FIELD.as_ref().clone());
    }
    TableSpec {
        schema: Schema::new(schema_fields),
        log_size: 2,
        cols: fields
            .into_iter()
            .zip(cols.iter().map(|(_, _, values)| fs(values)))
            .collect(),
        activator: activator.map(fs),
    }
}

/// `x [NOT] IN (2, 5, 7)` with input `x` (the last row inactive), claimed
/// result `b`, and `û` with flag `e` whose first `t` rows are active.
struct Case {
    negated: bool,
    x: [u64; 4],
    b: [u64; 4],
    union: [u64; 4],
    flag: [u64; 4],
    t: u64,
}

fn run(case: Case) -> Result<(), ark_piop::errors::SnarkError> {
    let list = [2, 5, 7].map(|v| ScalarValue::UInt64(Some(v))).to_vec();
    let gadget = LongListNode::<B>::new(list, case.negated);
    let sort_id = gadget.sort_gadget.id();
    let gadget: Arc<Node<B>> = Arc::new(Node::Gadget(Arc::new(gadget)));
    let id = gadget.id();
    let union_act: Vec<u64> = (0..4).map(|row| u64::from(row < case.t)).collect();
    let rotated: Vec<u64> = (0..4).map(|row| case.union[(row + 1) % 4]).collect();
    let harness = GadgetHarness::<B>::builder(16)
        .with_gadget(gadget)
        .with_table(
            id,
            INPUT_LABEL,
            table(&[("x", DataType::UInt64, &case.x)], Some(&[1, 1, 1, 0])),
        )
        .with_table(
            id,
            OUTPUT_LABEL,
            table(&[("b", DataType::Boolean, &case.b)], None),
        )
        .with_table(
            id,
            UNION_LABEL,
            table(
                &[
                    ("k", DataType::UInt64, &case.union),
                    (FLAG_COL, DataType::Boolean, &case.flag),
                ],
                Some(&union_act),
            ),
        )
        .with_table(id, ACTIVE_ROWS_LABEL, active_rows(case.t))
        .with_table(
            sort_id,
            ROTATED_INPUT_LABEL,
            table(&[("k", DataType::UInt64, &rotated)], None),
        )
        .build();
    run_gadget_pipeline(harness)
}

/// Inputs 5, 3, 7 on the active rows: `û` is 2, 3, 5, 7.
fn honest(negated: bool) -> Case {
    Case {
        negated,
        x: [5, 3, 7, 9],
        b: if negated { [0, 1, 0, 0] } else { [1, 0, 1, 0] },
        union: [2, 3, 5, 7],
        flag: [1, 0, 1, 1],
        t: 4,
    }
}

#[test]
fn an_honest_in_list_verifies() {
    run(honest(false)).expect("an honest IN list verifies");
}

#[test]
fn an_honest_not_in_list_verifies() {
    run(honest(true)).expect("an honest NOT IN list verifies");
}

#[test]
fn a_forged_result_is_rejected() {
    assert_rejected(run(Case {
        b: [1, 1, 1, 0],
        ..honest(false)
    }));
}

#[test]
fn a_result_on_an_inactive_row_is_rejected() {
    assert_rejected(run(Case {
        b: [1, 0, 1, 1],
        ..honest(false)
    }));
}

#[test]
fn a_flag_on_a_value_outside_the_list_is_rejected() {
    assert_rejected(run(Case {
        b: [1, 1, 1, 0],
        flag: [1, 1, 1, 1],
        ..honest(false)
    }));
}

#[test]
fn a_flag_missing_a_list_value_is_rejected() {
    assert_rejected(run(Case {
        b: [0, 0, 1, 0],
        flag: [1, 0, 0, 1],
        ..honest(false)
    }));
}

/// `û` holds 5 twice, flagged once: the flags still count `S` once each, and
/// the input row 5 is looked up at the unflagged copy.
#[test]
fn a_repeated_union_value_is_rejected() {
    assert_rejected(run(Case {
        x: [5, 7, 2, 9],
        b: [0, 1, 1, 0],
        union: [2, 5, 5, 7],
        flag: [1, 0, 1, 1],
        t: 4,
        negated: false,
    }));
}

/// A padding row of `û` holds 5 and carries its flag: the flags still count
/// `S` once each, the active rows are distinct, and the input row 5 is looked
/// up at the unflagged active copy.
#[test]
fn a_flag_on_a_padding_row_is_rejected() {
    assert_rejected(run(Case {
        x: [5, 7, 2, 9],
        b: [0, 1, 1, 0],
        union: [2, 5, 7, 5],
        flag: [1, 0, 1, 1],
        t: 3,
        negated: false,
    }));
}

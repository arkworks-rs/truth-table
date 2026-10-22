//! The ORDER BY gadget on hand-built four-row tables. The harness skips
//! gadget planning, so each test supplies the sort check's hints itself; a
//! forged hint reaches prover and verifier alike, as a committed witness
//! does in a real proof.

use std::sync::Arc;

use arithmetic::ACTIVATOR_FIELD;
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, arithmetic::errors::DataTypeError, errors::SnarkError,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion_common::DFSchema;
use datafusion_expr::{LogicalPlan, Sort, col, logical_plan::EmptyRelation};

use super::{GadgetNode, INPUT_LABEL, INPUT_SORT_EXPRS, OUTPUT_LABEL};
use crate::{
    irs::nodes::{IsNode, Node, utils::contig_sort},
    test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline},
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

fn table(name: &str, values: [i64; 4]) -> TableSpec<F> {
    let field = Arc::new(Field::new(name, DataType::Int64, false));
    TableSpec {
        schema: Schema::new(vec![
            field.as_ref().clone(),
            ACTIVATOR_FIELD.as_ref().clone(),
        ]),
        log_size: 2,
        cols: vec![(field, values.into_iter().map(F::from).collect())],
        activator: Some(vec![F::from(1u64); 4]),
    }
}

/// The output's active-row count, as the Sort node commits it.
fn active_rows(s: u64) -> TableSpec<F> {
    let field = Arc::new(Field::new("active_rows", DataType::UInt64, false));
    TableSpec {
        schema: Schema::new(vec![field.as_ref().clone()]),
        log_size: 0,
        cols: vec![(field, vec![F::from(s)])],
        activator: None,
    }
}

fn rotate(values: [i64; 4]) -> [i64; 4] {
    [values[1], values[2], values[3], values[0]]
}

/// The rotation hint: no activator, as the sort check supplies the mask.
fn rotated_table(values: [i64; 4]) -> TableSpec<F> {
    TableSpec {
        activator: None,
        schema: Schema::new(vec![Field::new("key", DataType::Int64, false)]),
        ..table("key", values)
    }
}

/// An ORDER BY on `key` (`asc` or descending) whose output is `output`. The
/// sort check's helper table is `helper` and its rotation hint is
/// `rotated`; `key_name` is the column the sort expressions name.
fn harness(
    asc: bool,
    output: [i64; 4],
    helper: [i64; 4],
    rotated: [i64; 4],
    key_name: &str,
) -> GadgetHarness<B> {
    let schema =
        DFSchema::try_from(Schema::new(vec![Field::new("key", DataType::Int64, false)])).unwrap();
    let sort = Sort {
        expr: vec![col("key").sort(asc, false)],
        input: Arc::new(LogicalPlan::EmptyRelation(EmptyRelation {
            produce_one_row: false,
            schema: Arc::new(schema),
        })),
        fetch: None,
    };
    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(sort))));
    let root = gadget.id();
    let sort_check = gadget.children()[0].id();
    GadgetHarness::<B>::builder(16)
        .with_gadget(gadget)
        .with_table(root, INPUT_LABEL, table("key", [2, 4, 1, 3]))
        .with_table(root, OUTPUT_LABEL, table("key", output))
        .with_table(root, INPUT_SORT_EXPRS, table(key_name, [2, 4, 1, 3]))
        .with_table(sort_check, contig_sort::TABLE_LABEL, table("key", helper))
        .with_table(root, contig_sort::ACTIVE_ROWS_LABEL, active_rows(4))
        .with_table(
            sort_check,
            contig_sort::ROTATED_INPUT_LABEL,
            rotated_table(rotated),
        )
        .build()
}

#[test]
fn sorted_output_is_accepted_in_both_directions() {
    let up = [1, 2, 3, 4];
    run_gadget_pipeline(harness(true, up, up, rotate(up), "key")).unwrap();
    let down = [4, 3, 2, 1];
    run_gadget_pipeline(harness(false, down, down, rotate(down), "key")).unwrap();
}

#[test]
fn a_sorted_helper_does_not_vouch_for_an_unsorted_output() {
    let sorted = [1, 2, 3, 4];
    let result = run_gadget_pipeline(harness(true, [2, 4, 1, 3], sorted, rotate(sorted), "key"));
    assert!(result.is_err());
}

#[test]
fn an_unsorted_output_with_a_matching_rotation_is_rejected() {
    let unsorted = [2, 4, 1, 3];
    let result = run_gadget_pipeline(harness(true, unsorted, unsorted, rotate(unsorted), "key"));
    assert!(result.is_err());
}

#[test]
fn a_key_that_is_not_an_output_column_is_not_supported() {
    let sorted = [1, 2, 3, 4];
    let result = run_gadget_pipeline(harness(true, sorted, sorted, rotate(sorted), "key + 1"));
    assert!(matches!(
        result,
        Err(SnarkError::DataTypeError(DataTypeError::NotSupported(_)))
    ));
}

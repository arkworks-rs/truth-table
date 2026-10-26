//! The ORDER BY gadget on hand-built four-row tables. The harness skips
//! gadget planning, so each test supplies the sort check's hints itself; a
//! forged hint reaches prover and verifier alike, as a committed witness
//! does in a real proof.

use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_FIELD,
    encoding::{STRING_LENGTH_SUFFIX, encode_arrow_array_to_field},
};
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, arithmetic::errors::DataTypeError, errors::SnarkError,
};
use datafusion::arrow::array::{ArrayRef, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion_common::Column;

use super::{
    GadgetNode, INPUT_LABEL, KeyOrder, OUTPUT_LABEL, SortKey, rank_super_label, sort_key_name,
};
use crate::{
    irs::nodes::{
        IsNode, Node,
        utils::contig_sort::{
            self,
            tests::{active_rows, assert_rejected},
        },
    },
    test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline},
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

fn spec(cols: Vec<(Field, Vec<F>)>, activator: bool) -> TableSpec<F> {
    let mut fields: Vec<Field> = cols.iter().map(|(field, _)| field.clone()).collect();
    if activator {
        fields.push(ACTIVATOR_FIELD.as_ref().clone());
    }
    TableSpec {
        schema: Schema::new(fields),
        log_size: 2,
        cols: cols
            .into_iter()
            .map(|(field, values)| (Arc::new(field), values))
            .collect(),
        activator: activator.then(|| vec![F::from(1u64); 4]),
    }
}

fn ints(name: &str, data_type: DataType, values: [u64; 4]) -> (Field, Vec<F>) {
    (
        Field::new(name, data_type, false),
        values.into_iter().map(F::from).collect(),
    )
}

fn rotate(values: [u64; 4]) -> [u64; 4] {
    [values[1], values[2], values[3], values[0]]
}

/// An ORDER BY on one key over `input`, whose output is `output`, with the
/// sort check's committed table `committed` and rotation hint `rotated`
/// (both of key 0), and `extra` tables for the root.
fn run(
    key: SortKey,
    input: TableSpec<F>,
    output: TableSpec<F>,
    committed: (Field, Vec<F>),
    rotated: (Field, Vec<F>),
    extra: Vec<(String, TableSpec<F>)>,
) -> Result<(), SnarkError> {
    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(vec![key]))));
    let root = gadget.id();
    let sort_check = gadget.children()[0].id();
    let mut builder = GadgetHarness::<B>::builder(16)
        .with_gadget(gadget)
        .with_table(root, INPUT_LABEL, input)
        .with_table(root, OUTPUT_LABEL, output)
        .with_table(root, contig_sort::ACTIVE_ROWS_LABEL, active_rows(4))
        .with_table(
            sort_check,
            contig_sort::TABLE_LABEL,
            spec(vec![committed], false),
        )
        .with_table(
            sort_check,
            contig_sort::ROTATED_INPUT_LABEL,
            spec(vec![rotated], false),
        );
    for (label, table) in extra {
        builder = builder.with_table(root, &label, table);
    }
    run_gadget_pipeline(builder.build())
}

fn int_key(asc: bool) -> SortKey {
    SortKey {
        column: Column::new_unqualified("key"),
        asc,
        order: KeyOrder::Value,
    }
}

/// An integer ORDER BY whose output is `output`, with a sort check table
/// `helper` the gadget must replace by the output's column.
fn run_int(
    asc: bool,
    output: [u64; 4],
    helper: [u64; 4],
    rotated: [u64; 4],
) -> Result<(), SnarkError> {
    let key = sort_key_name(0);
    run(
        int_key(asc),
        spec(vec![ints("key", DataType::Int64, [2, 4, 1, 3])], true),
        spec(vec![ints("key", DataType::Int64, output)], true),
        ints(&key, DataType::Int64, helper),
        ints(&key, DataType::Int64, rotated),
        Vec::new(),
    )
}

#[test]
fn sorted_output_is_accepted_in_both_directions() {
    let up = [1, 2, 3, 4];
    run_int(true, up, up, rotate(up)).unwrap();
    let down = [4, 3, 2, 1];
    run_int(false, down, down, rotate(down)).unwrap();
}

#[test]
fn a_sorted_helper_does_not_vouch_for_an_unsorted_output() {
    let sorted = [1, 2, 3, 4];
    assert!(run_int(true, [2, 4, 1, 3], sorted, rotate(sorted)).is_err());
}

#[test]
fn an_unsorted_output_with_a_matching_rotation_is_rejected() {
    let unsorted = [2, 4, 1, 3];
    assert!(run_int(true, unsorted, unsorted, rotate(unsorted)).is_err());
}

#[test]
fn a_key_that_is_not_an_output_column_is_not_supported() {
    let sorted = [1, 2, 3, 4];
    let key = sort_key_name(0);
    let result = run(
        SortKey {
            column: Column::new_unqualified("other"),
            ..int_key(true)
        },
        spec(vec![ints("key", DataType::Int64, [2, 4, 1, 3])], true),
        spec(vec![ints("key", DataType::Int64, sorted)], true),
        ints(&key, DataType::Int64, sorted),
        ints(&key, DataType::Int64, rotate(sorted)),
        Vec::new(),
    );
    assert!(
        matches!(
            result,
            Err(SnarkError::DataTypeError(DataTypeError::NotSupported(_)))
        ),
        "got {result:?}"
    );
}

/// The base column's strings, in rank order: their rank is their index.
const BASE: [&str; 4] = ["FRANCE", "GERMANY", "JAPAN", "PERU"];

/// The hash slot and length of each base string.
fn encoded_base() -> (Vec<F>, Vec<F>) {
    let array: ArrayRef = Arc::new(StringArray::from(BASE.to_vec()));
    let segments = encode_arrow_array_to_field::<F>(&array).unwrap();
    assert_eq!(segments[1].suffix, STRING_LENGTH_SUFFIX, "one hash slot");
    (
        segments[0].iter_values().collect(),
        segments[1].iter_values().collect(),
    )
}

/// A table of one string column holding the base strings of `ranks`.
fn strings(ranks: [usize; 4]) -> TableSpec<F> {
    let (hashes, lengths) = encoded_base();
    spec(
        vec![
            (
                Field::new("name", DataType::Utf8, false),
                ranks.iter().map(|&r| hashes[r]).collect(),
            ),
            (
                Field::new(format!("name{STRING_LENGTH_SUFFIX}"), DataType::Utf8, false),
                ranks.iter().map(|&r| lengths[r]).collect(),
            ),
        ],
        true,
    )
}

/// The base table's side of the rank lookup: hash slot, length and rank.
fn base_side() -> TableSpec<F> {
    let (hashes, lengths) = encoded_base();
    let ranks = (0..4u64).map(F::from).collect();
    spec(
        vec![
            (Field::new("rank_lookup_0", DataType::Int64, true), hashes),
            (Field::new("rank_lookup_1", DataType::Int64, true), lengths),
            (Field::new("rank_lookup_2", DataType::Int64, true), ranks),
        ],
        true,
    )
}

/// `ORDER BY name` (`asc` or descending) over a string sorted on its rank:
/// the output holds the base strings of `output`, and the sort check sorts
/// `rk_out`.
fn run_rank(asc: bool, output: [usize; 4], rk_out: [u64; 4]) -> Result<(), SnarkError> {
    let key = sort_key_name(0);
    run(
        SortKey {
            column: Column::new_unqualified("name"),
            asc,
            order: KeyOrder::Rank,
        },
        strings([2, 0, 3, 1]),
        strings(output),
        ints(&key, DataType::UInt32, rk_out),
        ints(&key, DataType::UInt32, rotate(rk_out)),
        vec![(rank_super_label(0), base_side())],
    )
}

#[test]
fn strings_sorted_on_their_ranks_are_accepted() {
    run_rank(true, [0, 1, 2, 3], [0, 1, 2, 3]).unwrap();
    run_rank(false, [3, 2, 1, 0], [3, 2, 1, 0]).unwrap();
}

#[test]
fn a_rank_of_another_string_is_rejected() {
    // GERMANY before FRANCE, each holding the other's rank: the ranks sort,
    // but (GERMANY, 0) is not a row of the base table.
    assert_rejected(run_rank(true, [1, 0, 2, 3], [0, 1, 2, 3]));
}

#[test]
fn unsorted_strings_with_their_own_ranks_are_rejected() {
    assert_rejected(run_rank(true, [1, 0, 2, 3], [1, 0, 2, 3]));
}

#[test]
fn a_key_is_told_apart_from_same_named_columns_by_its_qualifier() {
    let columns = [
        (Some("n1".to_string()), "n_name"),
        (Some("n2".to_string()), "n_name"),
        (None, "c"),
    ];
    let key = |column: Column| SortKey {
        column,
        asc: true,
        order: KeyOrder::Rank,
    };
    let index = |column| key(column).index_in(columns.iter().cloned());
    assert_eq!(index(Column::new(Some("n2"), "n_name")).unwrap(), 1);
    assert_eq!(index(Column::new(Some("t"), "c")).unwrap(), 2);
    for unresolved in [
        Column::new_unqualified("n_name"),
        Column::new(Some("n3"), "n_name"),
        Column::new_unqualified("d"),
    ] {
        assert!(matches!(
            index(unresolved),
            Err(SnarkError::DataTypeError(DataTypeError::NotSupported(_)))
        ));
    }
}

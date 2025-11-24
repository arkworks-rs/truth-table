use super::{build_tie_dataframe, shift_dataframe};
use datafusion::arrow::{
    array::{Array, ArrayRef, BooleanArray, Int32Array},
    compute,
    datatypes::{DataType, Field, Schema},
    record_batch::RecordBatch,
};
use datafusion::datasource::MemTable;
use datafusion::prelude::{DataFrame, SessionContext};
use futures::executor::block_on;
use std::sync::Arc;

/// Build a DataFrame from row-wise i32 data.
fn build_df_from_rows(rows: &[Vec<i32>]) -> DataFrame {
    if rows.is_empty() {
        let schema = Arc::new(Schema::new(Vec::<Field>::new()));
        let batch = RecordBatch::try_new(schema.clone(), Vec::new()).expect("empty batch");
        let mem_table = MemTable::try_new(schema, vec![vec![batch]]).expect("empty memtable");
        let ctx = SessionContext::new();
        return ctx.read_table(Arc::new(mem_table)).expect("empty df");
    }

    let col_count = rows[0].len();
    let mut columns: Vec<ArrayRef> = Vec::new();
    for col_idx in 0..col_count {
        let col_data: Vec<i32> = rows.iter().map(|r| r[col_idx]).collect();
        columns.push(Arc::new(Int32Array::from(col_data)) as ArrayRef);
    }

    let schema = Arc::new(Schema::new(
        (0..col_count)
            .map(|i| Field::new(format!("c{}", i + 1), DataType::Int32, false))
            .collect::<Vec<Field>>(),
    ));
    let batch = RecordBatch::try_new(schema.clone(), columns).expect("build input batch from rows");
    let mem_table =
        MemTable::try_new(schema, vec![vec![batch]]).expect("create mem table for input");
    let ctx = SessionContext::new();
    ctx.read_table(Arc::new(mem_table))
        .expect("build input dataframe")
}

fn collect_int_columns(df: DataFrame) -> Vec<Vec<Option<i32>>> {
    let batches = block_on(df.collect()).expect("collect df");
    if batches.is_empty() {
        return Vec::new();
    }
    let schema = batches[0].schema();
    let batch = compute::concat_batches(&schema, &batches).expect("concat batches");
    (0..batch.num_columns())
        .map(|col_idx| {
            batch
                .column(col_idx)
                .as_any()
                .downcast_ref::<Int32Array>()
                .expect("int col")
                .iter()
                .collect::<Vec<_>>()
        })
        .collect()
}

fn collect_bool_columns(df: DataFrame) -> Vec<Vec<Option<bool>>> {
    let batches = block_on(df.collect()).expect("collect df");
    if batches.is_empty() {
        return Vec::new();
    }
    let schema = batches[0].schema();
    let batch = compute::concat_batches(&schema, &batches).expect("concat batches");
    (0..batch.num_columns())
        .map(|col_idx| {
            batch
                .column(col_idx)
                .as_any()
                .downcast_ref::<BooleanArray>()
                .expect("bool col")
                .iter()
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Assert a shift case by supplying input rows and expected output rows.
fn assert_shift_case(rows: &[Vec<i32>], expected_rows: &[Vec<i32>], description: &str) {
    let input_df = build_df_from_rows(rows);
    let shifted = shift_dataframe(&input_df);
    let collected = collect_int_columns(shifted);
    let expected = transpose_rows(expected_rows);
    // Comment: Input rows: {rows:?}. Expected shifted output: {expected_rows:?}.
    assert_eq!(collected, expected, "shift case failed: {}", description);
}

/// Assert a tie case by supplying input rows and the expected tie columns.
fn assert_tie_case(rows: &[Vec<i32>], expected_ties: &[Vec<bool>], description: &str) {
    let input_df = build_df_from_rows(rows);
    let tie_df = build_tie_dataframe(&input_df);
    let collected = collect_bool_columns(tie_df);
    let expected: Vec<Vec<Option<bool>>> = expected_ties
        .iter()
        .map(|col| col.iter().map(|v| Some(*v)).collect())
        .collect();
    // Comment: Input rows: {rows:?}. Expected tie columns: {expected_ties:?}.
    assert_eq!(collected, expected, "tie case failed: {}", description);
}

fn transpose_rows(rows: &[Vec<i32>]) -> Vec<Vec<Option<i32>>> {
    if rows.is_empty() {
        return Vec::new();
    }
    let col_count = rows[0].len();
    let mut cols: Vec<Vec<Option<i32>>> = vec![Vec::new(); col_count];
    for row in rows {
        for (i, v) in row.iter().enumerate() {
            cols[i].push(Some(*v));
        }
    }
    cols
}

#[test]
fn shift_dataframe_wraps_first_row_to_end_four_rows() {
    // Four-row table, circular shift (row 0 wraps to end).
    // Input:  (1,5,9), (1,5,9), (1,6,9), (2,6,9)
    // Output: (1,5,9), (1,6,9), (2,6,9), (1,5,9)
    assert_shift_case(
        &vec![vec![1, 5, 9], vec![1, 5, 9], vec![1, 6, 9], vec![2, 6, 9]],
        &vec![vec![1, 5, 9], vec![1, 6, 9], vec![2, 6, 9], vec![1, 5, 9]],
        "four-row shift",
    );
}

#[test]
fn shift_dataframe_wraps_first_row_to_end_three_rows() {
    // Three-row table, circular shift.
    // Input:  (3,3), (3,4), (4,4)
    // Output: (3,4), (4,4), (3,3)
    assert_shift_case(
        &vec![vec![3, 3], vec![3, 4], vec![4, 4]],
        &vec![vec![3, 4], vec![4, 4], vec![3, 3]],
        "three-row shift",
    );
}

#[test]
fn tie_dataframe_full_match_on_first_pair() {
    // Input rows: (1,5,9), (1,5,9), (1,6,9), (2,6,9)
    // Expected ties (n-1 columns, last row always false):
    // tie_1: [true, true, false, false]   // c1 matches next row for rows 0 and 1
    // tie_2: [true, false, false, false]  // (c1,c2) matches only for row 0
    assert_tie_case(
        &vec![vec![1, 5, 9], vec![1, 5, 9], vec![1, 6, 9], vec![2, 6, 9]],
        &vec![
            vec![true, true, false, false],
            vec![true, false, false, false],
        ],
        "prefix ties with full match on first pair of rows",
    );
}

#[test]
fn tie_dataframe_middle_duplicate_pair() {
    // Input rows: (3,3), (3,4), (3,4), (4,4)
    // Expected ties (only one tie column because input has two columns):
    // tie_1: [true, true, false, false]   // c1 matches next row for rows 0 and 1
    assert_tie_case(
        &vec![vec![3, 3], vec![3, 4], vec![3, 4], vec![4, 4]],
        &vec![
            vec![true, true, false, false],
        ],
        "prefix ties with middle duplicate pair",
    );
}

#[test]
fn tie_dataframe_complex() {
    // Input columns (c1, c2, c3):
    // c1: [1, 2, 2, 2, 7, 8, 8, 9, 10]
    // c2: [30, 9, 13, 13, 5, 2, 2, 65, 49]
    // c3: [97, 5, 22, 27, 19, 31, 54, 1, 11]
    //
    // Expected tie indicators (row compares against next row; last row always false):
    // tie_1: [0,1,1,0,0,1,0,0,0]
    // tie_2: [0,0,1,0,0,1,0,0,0]
    let rows = vec![
        vec![1, 30, 97],
        vec![2, 9, 5],
        vec![2, 13, 22],
        vec![2, 13, 27],
        vec![7, 5, 19],
        vec![8, 2, 31],
        vec![8, 2, 54],
        vec![9, 65, 1],
        vec![10, 49, 11],
    ];

    assert_tie_case(
        &rows,
        &vec![
            vec![false, true, true, false, false, true, false, false, false],
            vec![false, false, true, false, false, true, false, false, false],
        ],
        "complex tie detection across three columns",
    );
}

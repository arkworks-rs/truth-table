use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use datafusion::{
    arrow::{
        array::{ArrayRef, BooleanArray, Int32Array, Int64Array},
        compute::concat_batches,
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    },
    prelude::SessionContext,
};

use crate::irs::nodes::gadget::utils::sort::hints::{rotate, tie_indicator};

fn build_df(
    ctx: &SessionContext,
    fields: Vec<Field>,
    columns: Vec<ArrayRef>,
) -> datafusion_common::Result<datafusion::prelude::DataFrame> {
    let schema = Arc::new(Schema::new(fields));
    let batch = RecordBatch::try_new(Arc::clone(&schema), columns)?;
    ctx.read_batch(batch)
}

async fn assert_rotated_int_bool(
    df: datafusion::prelude::DataFrame,
    expected_names: Vec<&str>,
    expected_int_cols: Vec<Vec<i32>>,
    expected_activator: Vec<bool>,
) {
    let out = rotate(df, Vec::new()).unwrap();
    let batches = out.collect().await.unwrap();
    let combined = concat_batches(&batches[0].schema(), &batches).unwrap();

    let schema = combined.schema();
    let field_names = schema
        .fields()
        .iter()
        .map(|field| field.name().to_string())
        .collect::<Vec<_>>();
    let expected_names = expected_names
        .iter()
        .map(|name| (*name).to_string())
        .collect::<Vec<_>>();
    assert_eq!(field_names, expected_names);
    assert_eq!(expected_int_cols.len() + 1, combined.num_columns());

    for (idx, expected) in expected_int_cols.iter().enumerate() {
        let vals = combined
            .column(idx)
            .as_any()
            .downcast_ref::<Int32Array>()
            .unwrap();
        let actual = (0..vals.len())
            .map(|row| vals.value(row))
            .collect::<Vec<_>>();
        assert_eq!(&actual, expected);
    }

    let activator_vals = combined
        .column(expected_int_cols.len())
        .as_any()
        .downcast_ref::<BooleanArray>()
        .unwrap();
    let activator_values = (0..activator_vals.len())
        .map(|idx| activator_vals.value(idx))
        .collect::<Vec<_>>();
    assert_eq!(activator_values, expected_activator);
}

async fn assert_tie_indicator(
    df: datafusion::prelude::DataFrame,
    expected_names: Vec<&str>,
    expected_cols: Vec<Vec<bool>>,
) {
    let out = tie_indicator(df, Vec::new()).unwrap();
    let batches = out.collect().await.unwrap();
    let combined = concat_batches(&batches[0].schema(), &batches).unwrap();

    let schema = combined.schema();
    let field_names = schema
        .fields()
        .iter()
        .map(|field| field.name().to_string())
        .collect::<Vec<_>>();
    let expected_names = expected_names
        .iter()
        .map(|name| (*name).to_string())
        .collect::<Vec<_>>();
    assert_eq!(field_names, expected_names);
    assert_eq!(combined.num_columns(), expected_cols.len());

    for (idx, expected) in expected_cols.iter().enumerate() {
        let vals = combined
            .column(idx)
            .as_any()
            .downcast_ref::<BooleanArray>()
            .unwrap();
        let actual = (0..vals.len())
            .map(|row| vals.value(row))
            .collect::<Vec<_>>();
        assert_eq!(&actual, expected);
    }
}

#[tokio::test]
async fn rotate_single_column_with_activator() {
    let ctx = SessionContext::new();
    let df = build_df(
        &ctx,
        vec![
            Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
            Field::new("x", DataType::Int32, false),
            Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
        ],
        vec![
            Arc::new(Int64Array::from(vec![0, 1, 2, 3])) as ArrayRef,
            Arc::new(Int32Array::from(vec![10, 20, 30, 40])) as ArrayRef,
            Arc::new(BooleanArray::from(vec![true, false, true, false])) as ArrayRef,
        ],
    )
    .unwrap();

    assert_rotated_int_bool(
        df,
        vec!["x", ACTIVATOR_COL_NAME],
        vec![vec![20, 30, 40, 10]],
        vec![false, true, false, true],
    )
    .await;
}

#[tokio::test]
async fn rotate_multiple_columns() {
    let ctx = SessionContext::new();
    let df = build_df(
        &ctx,
        vec![
            Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
            Field::new("a", DataType::Int32, false),
            Field::new("b", DataType::Int32, false),
            Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
        ],
        vec![
            Arc::new(Int64Array::from(vec![0, 1, 2])) as ArrayRef,
            Arc::new(Int32Array::from(vec![1, 2, 3])) as ArrayRef,
            Arc::new(Int32Array::from(vec![10, 20, 30])) as ArrayRef,
            Arc::new(BooleanArray::from(vec![true, true, false])) as ArrayRef,
        ],
    )
    .unwrap();

    assert_rotated_int_bool(
        df,
        vec!["a", "b", ACTIVATOR_COL_NAME],
        vec![vec![2, 3, 1], vec![20, 30, 10]],
        vec![true, false, true],
    )
    .await;
}

#[tokio::test]
async fn rotate_requires_row_id() {
    let ctx = SessionContext::new();
    let df = build_df(
        &ctx,
        vec![Field::new("x", DataType::Int32, false)],
        vec![Arc::new(Int32Array::from(vec![1, 2, 3])) as ArrayRef],
    )
    .unwrap();

    let err = rotate(df, Vec::new()).unwrap_err();
    assert!(
        err.to_string().contains(ROW_ID_COL_NAME),
        "expected rotate error to mention row id"
    );
}

#[tokio::test]
async fn tie_indicator_basic_prefixes() {
    let ctx = SessionContext::new();
    let df = build_df(
        &ctx,
        vec![
            Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
            Field::new("a", DataType::Int32, false),
            Field::new("b", DataType::Int32, false),
            Field::new("c", DataType::Int32, false),
        ],
        vec![
            Arc::new(Int64Array::from(vec![0, 1, 2, 3])) as ArrayRef,
            Arc::new(Int32Array::from(vec![1, 1, 1, 2])) as ArrayRef,
            Arc::new(Int32Array::from(vec![9, 9, 8, 8])) as ArrayRef,
            Arc::new(Int32Array::from(vec![5, 7, 7, 7])) as ArrayRef,
        ],
    )
    .unwrap();

    assert_tie_indicator(
        df,
        vec!["tie_1", "tie_2"],
        vec![
            vec![true, true, false, false],
            vec![true, false, false, false],
        ],
    )
    .await;
}

#[tokio::test]
async fn tie_indicator_three_prefixes() {
    let ctx = SessionContext::new();
    let df = build_df(
        &ctx,
        vec![
            Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
            Field::new("a", DataType::Int32, false),
            Field::new("b", DataType::Int32, false),
            Field::new("c", DataType::Int32, false),
            Field::new("d", DataType::Int32, false),
        ],
        vec![
            Arc::new(Int64Array::from(vec![0, 1, 2, 3])) as ArrayRef,
            Arc::new(Int32Array::from(vec![7, 7, 7, 7])) as ArrayRef,
            Arc::new(Int32Array::from(vec![1, 1, 1, 2])) as ArrayRef,
            Arc::new(Int32Array::from(vec![2, 3, 3, 3])) as ArrayRef,
            Arc::new(Int32Array::from(vec![9, 9, 4, 4])) as ArrayRef,
        ],
    )
    .unwrap();

    assert_tie_indicator(
        df,
        vec!["tie_1", "tie_2", "tie_3"],
        vec![
            vec![true, true, true, false],
            vec![true, true, false, false],
            vec![false, true, false, false],
        ],
    )
    .await;
}

#[tokio::test]
async fn tie_indicator_full_match_until_last_col() {
    let ctx = SessionContext::new();
    let df = build_df(
        &ctx,
        vec![
            Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
            Field::new("x", DataType::Int32, false),
            Field::new("y", DataType::Int32, false),
            Field::new("z", DataType::Int32, false),
        ],
        vec![
            Arc::new(Int64Array::from(vec![0, 1, 2])) as ArrayRef,
            Arc::new(Int32Array::from(vec![4, 4, 4])) as ArrayRef,
            Arc::new(Int32Array::from(vec![5, 5, 5])) as ArrayRef,
            Arc::new(Int32Array::from(vec![6, 6, 7])) as ArrayRef,
        ],
    )
    .unwrap();

    assert_tie_indicator(
        df,
        vec!["tie_1", "tie_2"],
        vec![vec![true, true, false], vec![true, true, false]],
    )
    .await;
}

#[tokio::test]
async fn tie_indicator_no_prefix_match() {
    let ctx = SessionContext::new();
    let df = build_df(
        &ctx,
        vec![
            Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
            Field::new("p", DataType::Int32, false),
            Field::new("q", DataType::Int32, false),
        ],
        vec![
            Arc::new(Int64Array::from(vec![0, 1, 2])) as ArrayRef,
            Arc::new(Int32Array::from(vec![1, 3, 5])) as ArrayRef,
            Arc::new(Int32Array::from(vec![2, 4, 6])) as ArrayRef,
        ],
    )
    .unwrap();

    assert_tie_indicator(df, vec!["tie_1"], vec![vec![false, false, false]]).await;
}

#[tokio::test]
async fn tie_indicator_single_row() {
    let ctx = SessionContext::new();
    let df = build_df(
        &ctx,
        vec![
            Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
            Field::new("a", DataType::Int32, false),
            Field::new("b", DataType::Int32, false),
            Field::new("c", DataType::Int32, false),
        ],
        vec![
            Arc::new(Int64Array::from(vec![0])) as ArrayRef,
            Arc::new(Int32Array::from(vec![9])) as ArrayRef,
            Arc::new(Int32Array::from(vec![9])) as ArrayRef,
            Arc::new(Int32Array::from(vec![9])) as ArrayRef,
        ],
    )
    .unwrap();

    assert_tie_indicator(df, vec!["tie_1", "tie_2"], vec![vec![false], vec![false]]).await;
}

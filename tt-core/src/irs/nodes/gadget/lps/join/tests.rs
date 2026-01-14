use std::sync::Arc;

use arithmetic::ROW_ID_COL_NAME;
use datafusion::{
    arrow::{
        array::{ArrayRef, Int32Array, Int64Array},
        compute::concat_batches,
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    },
    prelude::SessionContext,
};
use datafusion_common::{Column, TableReference};
use datafusion_expr::{Expr, JoinType, LogicalPlan};

use super::hints::build_source_dfs;
use super::{SRC_LEFT_COL_NAME, SRC_RIGHT_COL_NAME};

fn build_df(
    ctx: &SessionContext,
    rows: &[(i64, i32)],
    alias: &str,
) -> datafusion_common::Result<datafusion::prelude::DataFrame> {
    let row_ids: Vec<i64> = rows.iter().map(|(row_id, _)| *row_id).collect();
    let keys: Vec<i32> = rows.iter().map(|(_, key)| *key).collect();
    let schema = Arc::new(Schema::new(vec![
        Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
        Field::new("key", DataType::Int32, false),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(Int64Array::from(row_ids)) as ArrayRef,
            Arc::new(Int32Array::from(keys)) as ArrayRef,
        ],
    )?;
    ctx.read_batch(batch)?.alias(alias)
}

async fn collect_i64_column(
    df: datafusion::prelude::DataFrame,
    col_name: &str,
) -> Vec<i64> {
    let batches = df.collect().await.expect("collect should succeed");
    if batches.is_empty() {
        return Vec::new();
    }
    let combined = concat_batches(&batches[0].schema(), &batches)
        .expect("concat should succeed");
    let col = combined
        .column_by_name(col_name)
        .expect("expected column")
        .as_any()
        .downcast_ref::<Int64Array>()
        .expect("expected i64 column");
    (0..col.len()).map(|idx| col.value(idx)).collect()
}

async fn assert_source_mapping(
    left_rows: &[(i64, i32)],
    right_rows: &[(i64, i32)],
    expected_left: &[i64],
    expected_right: &[i64],
) {
    // Build two small tables with (row_id, key) pairs, perform an inner join on key,
    // then assert that the src_* outputs line up with the joined row_ids.
    let ctx = SessionContext::new();
    let left_df = build_df(&ctx, left_rows, "l").unwrap();
    let right_df = build_df(&ctx, right_rows, "r").unwrap();

    let left_key = Expr::Column(Column::new(
        Some(TableReference::bare("l")),
        "key",
    ));
    let right_key = Expr::Column(Column::new(
        Some(TableReference::bare("r")),
        "key",
    ));
    let join_df = left_df
        .clone()
        .join_on(
            right_df.clone(),
            JoinType::Inner,
            vec![left_key.eq(right_key)],
        )
        .expect("join should succeed");

    let join = match join_df.logical_plan() {
        LogicalPlan::Join(join) => join.clone(),
        _ => panic!("expected a join logical plan"),
    };
    let (left_src, right_src) =
        build_source_dfs(left_df, right_df, &join).expect("source dfs should build");
    let left_vals = collect_i64_column(left_src, SRC_LEFT_COL_NAME).await;
    let right_vals = collect_i64_column(right_src, SRC_RIGHT_COL_NAME).await;

    assert_eq!(left_vals, expected_left);
    assert_eq!(right_vals, expected_right);
}

#[tokio::test]
async fn source_mapping_basic_inner_join() {
    // Both sides have duplicated join keys, so the join output has a 2x2 Cartesian
    // product for key=1. The src_* columns report the original row_id values
    // from the left/right inputs in sorted (row_id) order.
    let left_rows = vec![(0, 1), (2, 1), (5, 2)];
    let right_rows = vec![(10, 1), (11, 1)];
    assert_source_mapping(
        &left_rows,
        &right_rows,
        &[0, 0, 2, 2],
        &[10, 11, 10, 11],
    )
    .await;
}

#[tokio::test]
async fn source_mapping_sorts_by_row_id() {
    // Row IDs are intentionally out of order on both sides; the helper should
    // sort by row_id and still report the original row_id values.
    let left_rows = vec![(5, 1), (1, 1)];
    let right_rows = vec![(20, 1), (10, 1)];
    assert_source_mapping(
        &left_rows,
        &right_rows,
        &[1, 1, 5, 5],
        &[10, 20, 10, 20],
    )
    .await;
}

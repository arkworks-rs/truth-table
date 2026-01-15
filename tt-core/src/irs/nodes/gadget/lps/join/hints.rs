use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use datafusion::functions_window::expr_fn::row_number;
use datafusion::prelude::DataFrame;
use datafusion_common::{Column, DataFusionError, Result as DataFusionResult, TableReference};
use datafusion_expr::{Expr, ExprFunctionExt, Join, JoinType, col, lit};

use super::{SRC_LEFT_COL_NAME, SRC_RIGHT_COL_NAME};

pub(crate) fn build_source_dfs(
    left: DataFrame,
    right: DataFrame,
    output: DataFrame,
    join: &Join,
) -> DataFusionResult<(DataFrame, DataFrame)> {
    // Build join predicates (equi-join pairs plus optional filter).
    let mut join_exprs: Vec<Expr> = join
        .on
        .iter()
        .map(|(left_expr, right_expr)| left_expr.clone().eq(right_expr.clone()))
        .collect();
    for expr in join.on.iter().flat_map(|(l, r)| [l, r]) {
        if expr_has_system_column(expr) {
            return Err(DataFusionError::Plan(
                "Join keys must not reference system columns".to_string(),
            ));
        }
    }
    if let Some(filter) = &join.filter {
        if expr_has_system_column(filter) {
            return Err(DataFusionError::Plan(
                "Join filters must not reference system columns".to_string(),
            ));
        }
        join_exprs.push(filter.clone());
    }

    let (left, left_row_id) = prepare_input(left, "left", "__left_row_id__")?;
    let (right, right_row_id) = prepare_input(right, "right", "__right_row_id__")?;

    // Execute the join so we can recover which left/right row_id contributed to each output row.
    let joined = left
        .join_on(right, join.join_type, join_exprs)
        .expect("join source mapping should succeed");

    // Sort by left/right row_id to match the plan-side ordering.
    let row_id_sort_exprs = vec![
        Expr::Column(left_row_id.clone()).sort(true, true),
        Expr::Column(right_row_id.clone()).sort(true, true),
    ];
    let sorted = joined.sort(row_id_sort_exprs.clone())?;

    // Assign a fresh row number in sorted order so we can align with the output row_id.
    let row_number_expr = row_number()
        .partition_by(Vec::new())
        .order_by(row_id_sort_exprs)
        .build()?
        .alias("__row_number__");
    let indexed = sorted.select(vec![
        Expr::Column(left_row_id).alias("left_row_id"),
        Expr::Column(right_row_id).alias("right_row_id"),
        row_number_expr,
    ])?;

    // Align the mapping with the output's __row_id__ so src_* match output rows.
    let mapping = indexed
        .select(vec![
            col("left_row_id"),
            col("right_row_id"),
            (col("__row_number__") - lit(1_i64)).alias(ROW_ID_COL_NAME),
        ])?
        .alias("__mapping__")?;
    let output = output.alias("__output__")?;
    let join_on = vec![
        Expr::Column(Column::new(
            Some(TableReference::bare("__output__")),
            ROW_ID_COL_NAME,
        ))
        .eq(Expr::Column(Column::new(
            Some(TableReference::bare("__mapping__")),
            ROW_ID_COL_NAME,
        ))),
    ];
    let aligned = output.join_on(mapping, JoinType::Inner, join_on)?;
    let aligned = aligned.sort(vec![
        Expr::Column(Column::new(
            Some(TableReference::bare("__output__")),
            ROW_ID_COL_NAME,
        ))
        .sort(true, true),
    ])?;

    let left_src = aligned.clone().select(vec![
        Expr::Column(Column::new(
            Some(TableReference::bare("__mapping__")),
            "left_row_id",
        ))
        .alias(SRC_LEFT_COL_NAME),
    ])?;
    let right_src = aligned.select(vec![
        Expr::Column(Column::new(
            Some(TableReference::bare("__mapping__")),
            "right_row_id",
        ))
        .alias(SRC_RIGHT_COL_NAME),
    ])?;
    Ok((left_src, right_src))
}

fn prepare_input(
    df: DataFrame,
    side: &str,
    row_id_alias: &str,
) -> DataFusionResult<(DataFrame, Column)> {
    let mut projection_exprs = Vec::new();
    let mut row_id_col: Option<Column> = None;
    for (qualifier, field) in df.schema().iter() {
        if field.name() == ACTIVATOR_COL_NAME {
            continue;
        }
        if field.name() == ROW_ID_COL_NAME {
            if row_id_col.is_some() {
                return Err(DataFusionError::Plan(format!(
                    "Join {side} input has multiple {ROW_ID_COL_NAME} columns"
                )));
            }
            projection_exprs.push(
                Expr::Column(Column::new(qualifier.cloned(), ROW_ID_COL_NAME)).alias(row_id_alias),
            );
            // Alias columns are unqualified in the projection.
            row_id_col = Some(Column::from_name(row_id_alias));
            continue;
        }
        projection_exprs.push(Expr::Column(Column::new(qualifier.cloned(), field.name())));
    }
    let Some(row_id_col) = row_id_col else {
        return Err(DataFusionError::Plan(format!(
            "Join {side} input is missing {ROW_ID_COL_NAME}"
        )));
    };
    let df = df.select(projection_exprs)?;
    Ok((df, row_id_col))
}

fn expr_has_system_column(expr: &Expr) -> bool {
    expr.column_refs()
        .iter()
        .any(|col| col.name == ACTIVATOR_COL_NAME || col.name == ROW_ID_COL_NAME)
}

#[cfg(test)]
mod tests {
    use super::build_source_dfs;
    use super::{SRC_LEFT_COL_NAME, SRC_RIGHT_COL_NAME};
    use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
    use datafusion::arrow::{
        array::{ArrayRef, Int32Array, Int64Array},
        compute::concat_batches,
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    };
    use datafusion::functions_window::expr_fn::row_number;
    use datafusion::prelude::SessionContext;
    use datafusion_common::{Column, TableReference};
    use datafusion_expr::{Expr, ExprFunctionExt, JoinType, LogicalPlan, col, lit};
    use std::sync::Arc;

    fn build_df(
        ctx: &SessionContext,
        rows: &[(i64, i32, i32)],
        alias: &str,
    ) -> datafusion_common::Result<datafusion::prelude::DataFrame> {
        let row_ids: Vec<i64> = rows.iter().map(|(row_id, _, _)| *row_id).collect();
        let keys: Vec<i32> = rows.iter().map(|(_, key, _)| *key).collect();
        let vals: Vec<i32> = rows.iter().map(|(_, _, val)| *val).collect();
        let schema = Arc::new(Schema::new(vec![
            Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
            Field::new("key", DataType::Int32, false),
            Field::new("val", DataType::Int32, false),
        ]));
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![
                Arc::new(Int64Array::from(row_ids)) as ArrayRef,
                Arc::new(Int32Array::from(keys)) as ArrayRef,
                Arc::new(Int32Array::from(vals)) as ArrayRef,
            ],
        )?;
        ctx.read_batch(batch)?.alias(alias)
    }

    async fn collect_i64_column(df: datafusion::prelude::DataFrame, col_name: &str) -> Vec<i64> {
        let batches = df.collect().await.expect("collect should succeed");
        if batches.is_empty() {
            return Vec::new();
        }
        let combined =
            concat_batches(&batches[0].schema(), &batches).expect("concat should succeed");
        let col = combined
            .column_by_name(col_name)
            .expect("expected column")
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("expected i64 column");
        (0..col.len()).map(|idx| col.value(idx)).collect()
    }

    fn join_plan_from_df(df: &datafusion::prelude::DataFrame) -> datafusion_expr::Join {
        match df.logical_plan() {
            LogicalPlan::Join(join) => join.clone(),
            _ => panic!("expected a join logical plan"),
        }
    }

    fn build_output_df(
        left_df: datafusion::prelude::DataFrame,
        right_df: datafusion::prelude::DataFrame,
        join_type: JoinType,
        left_key: Expr,
        right_key: Expr,
    ) -> datafusion::prelude::DataFrame {
        let prepare_input = |df: datafusion::prelude::DataFrame, row_id_label: &str| {
            let mut projection_exprs = Vec::new();
            for (qualifier, field) in df.schema().iter() {
                if field.name() == ROW_ID_COL_NAME {
                    projection_exprs.push(
                        Expr::Column(Column::new(qualifier.cloned(), ROW_ID_COL_NAME))
                            .alias(row_id_label),
                    );
                    continue;
                }
                projection_exprs.push(Expr::Column(Column::new(qualifier.cloned(), field.name())));
            }
            df.select(projection_exprs)
                .expect("output input projection should succeed")
        };

        let left_df = prepare_input(left_df, "__left_row_id__");
        let right_df = prepare_input(right_df, "__right_row_id__");
        let joined = left_df
            .join_on(right_df, join_type, vec![left_key.eq(right_key)])
            .expect("output join should succeed");

        let mut data_exprs = Vec::new();
        let mut left_row_id = None;
        let mut right_row_id = None;
        for (qualifier, field) in joined.schema().iter() {
            if field.name() == "__left_row_id__" {
                left_row_id = Some(Expr::Column(Column::new(qualifier.cloned(), field.name())));
                continue;
            }
            if field.name() == "__right_row_id__" {
                right_row_id = Some(Expr::Column(Column::new(qualifier.cloned(), field.name())));
                continue;
            }
            data_exprs.push(Expr::Column(Column::new(qualifier.cloned(), field.name())));
        }

        let row_id_sort_exprs = vec![
            left_row_id
                .expect("left row_id should exist")
                .sort(true, true),
            right_row_id
                .expect("right row_id should exist")
                .sort(true, true),
        ];
        let joined = joined
            .sort(row_id_sort_exprs.clone())
            .expect("output sort should succeed");

        let row_number_expr = row_number()
            .partition_by(Vec::new())
            .order_by(row_id_sort_exprs)
            .build()
            .expect("row_number should build")
            .alias("__row_number__");
        let mut projection_exprs = data_exprs;
        projection_exprs.push(lit(true).alias(ACTIVATOR_COL_NAME));
        projection_exprs.push(row_number_expr);
        let with_row_number = joined
            .select(projection_exprs)
            .expect("output row_number projection should succeed");

        let mut final_exprs = Vec::new();
        for (qualifier, field) in with_row_number.schema().iter() {
            if field.name() == "__row_number__" {
                continue;
            }
            final_exprs.push(Expr::Column(Column::new(qualifier.cloned(), field.name())));
        }
        final_exprs.push((col("__row_number__") - lit(1_i64)).alias(ROW_ID_COL_NAME));
        with_row_number
            .select(final_exprs)
            .expect("output row_id projection should succeed")
    }

    async fn assert_source_mapping(
        left_rows: &[(i64, i32, i32)],
        right_rows: &[(i64, i32, i32)],
        expected_left: &[i64],
        expected_right: &[i64],
    ) {
        let ctx = SessionContext::new();
        let left_df = build_df(&ctx, left_rows, "l").unwrap();
        let right_df = build_df(&ctx, right_rows, "r").unwrap();

        let left_key = Expr::Column(Column::new(Some(TableReference::bare("l")), "key"));
        let right_key = Expr::Column(Column::new(Some(TableReference::bare("r")), "key"));
        let join_df = left_df
            .clone()
            .join_on(
                right_df.clone(),
                JoinType::Inner,
                vec![left_key.clone().eq(right_key.clone())],
            )
            .expect("join should succeed");

        let join = join_plan_from_df(&join_df);
        let output_df = build_output_df(
            left_df.clone(),
            right_df.clone(),
            JoinType::Inner,
            left_key,
            right_key,
        );
        let (left_src, right_src) =
            build_source_dfs(left_df, right_df, output_df, &join).expect("source dfs should build");
        let left_vals = collect_i64_column(left_src, SRC_LEFT_COL_NAME).await;
        let right_vals = collect_i64_column(right_src, SRC_RIGHT_COL_NAME).await;

        assert_eq!(left_vals, expected_left);
        assert_eq!(right_vals, expected_right);
    }

    #[tokio::test]
    async fn source_mapping_basic_inner_join() {
        // Scenario: one-to-one join.
        // Inputs:
        // - left rows:  (row_id=10, key=1, val=100)
        // - right rows: (row_id=20, key=1, val=200)
        // Join on key == key, so the single output row maps to:
        // - left src row_id: 10
        // - right src row_id: 20
        assert_source_mapping(&[(10, 1, 100)], &[(20, 1, 200)], &[10], &[20]).await;
    }

    #[tokio::test]
    async fn source_mapping_duplicate_keys_cartesian() {
        // Scenario: duplicate keys on both sides.
        // Inputs:
        // - left rows:  (row_id=1, key=1, val=10), (row_id=3, key=1, val=11)
        // - right rows: (row_id=2, key=1, val=20), (row_id=4, key=1, val=21)
        // Join on key == key, so the output is a 2x2 Cartesian product.
        // Output ordering is by (left_row_id, right_row_id), so the src lists are:
        // - left src row_id:  1, 1, 3, 3
        // - right src row_id: 2, 4, 2, 4
        assert_source_mapping(
            &[(1, 1, 10), (3, 1, 11)],
            &[(2, 1, 20), (4, 1, 21)],
            &[1, 1, 3, 3],
            &[2, 4, 2, 4],
        )
        .await;
    }

    #[tokio::test]
    async fn source_mapping_no_matches_is_empty() {
        // Scenario: no matching keys.
        // Inputs:
        // - left rows:  (row_id=1, key=1, val=10)
        // - right rows: (row_id=2, key=2, val=20)
        // Join on key == key yields no rows, so both src outputs are empty.
        assert_source_mapping(&[(1, 1, 10)], &[(2, 2, 20)], &[], &[]).await;
    }
}

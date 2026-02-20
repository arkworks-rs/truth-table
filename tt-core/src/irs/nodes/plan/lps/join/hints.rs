use crate::irs::nodes::plan::lps::join::modes::JoinMode;
use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use datafusion::functions_window::expr_fn::row_number;
use datafusion::prelude::DataFrame;
use datafusion_common::Column;
use datafusion_expr::expr::Sort as SortExpr;
use datafusion_expr::{Expr, ExprFunctionExt, Join, JoinType, Operator, binary_expr, col, lit};

pub fn build_output_dataframe(left_df: DataFrame, right_df: DataFrame, join: &Join) -> DataFrame {
    // 1) Build the join predicates from the logical plan.
    let mut join_exprs: Vec<Expr> = join
        .on
        .iter()
        .map(|(left_expr, right_expr)| left_expr.clone().eq(right_expr.clone()))
        .collect();
    if let Some(filter) = &join.filter {
        join_exprs.push(filter.clone());
    }

    // 2) Filter out padding rows (activator = false), then strip system columns
    //    (activator/row_id) from inputs, but keep row_id
    //    under a unique name so we can build the new output row_id later.
    let prepare_input = |df: DataFrame, row_id_label: &str| {
        let df = df
            .filter(col(ACTIVATOR_COL_NAME).eq(lit(true)))
            .expect("join input activator filter should succeed");
        let mut projection_exprs = Vec::new();
        for (qualifier, field) in df.schema().iter() {
            if field.name() == ACTIVATOR_COL_NAME {
                continue;
            }
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
            .expect("join input activator projection should succeed")
    };

    let left_df = prepare_input(left_df, "__left_row_id__");
    let right_df = prepare_input(right_df, "__right_row_id__");

    // 3) Execute the join over data columns (system columns removed).
    let joined = left_df
        .join_on(right_df, join.join_type, join_exprs)
        .expect("join output should succeed");

    // 4) Build the output projection:
    //    - keep all joined data columns
    //    - sort by left/right row_id when present
    //    - assign a fresh 0-based __row_id__ in that sorted order
    //    - add a new __activator__ set to true for all real rows
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
        if field.name() == ACTIVATOR_COL_NAME || field.name() == ROW_ID_COL_NAME {
            continue;
        }
        data_exprs.push(Expr::Column(Column::new(qualifier.cloned(), field.name())));
    }

    // Sort by left/right row_id columns to make row_id assignment deterministic.
    let mut row_id_sort_exprs: Vec<SortExpr> = Vec::new();
    if let Some(left) = left_row_id {
        row_id_sort_exprs.push(left.sort(true, true));
    }
    if let Some(right) = right_row_id {
        row_id_sort_exprs.push(right.sort(true, true));
    }
    let joined = if row_id_sort_exprs.is_empty() {
        joined
    } else {
        joined
            .sort(row_id_sort_exprs.clone())
            .expect("join output sort should succeed")
    };

    // New activator is 1 for all real rows (no padding is applied here).
    let mut projection_exprs = data_exprs;
    projection_exprs.push(lit(true).alias(ACTIVATOR_COL_NAME));
    let row_number_expr = row_number()
        .partition_by(Vec::new())
        .order_by(row_id_sort_exprs)
        .build()
        .expect("join row_number window should build")
        .alias("__row_number__");
    projection_exprs.push(row_number_expr);

    let joined = joined
        .select(projection_exprs)
        .expect("join output activator projection should succeed");

    let mut final_exprs = Vec::new();
    for (qualifier, field) in joined.schema().iter() {
        if field.name() == "__row_number__" {
            continue;
        }
        final_exprs.push(Expr::Column(Column::new(qualifier.cloned(), field.name())));
    }
    final_exprs.push(
        binary_expr(col("__row_number__"), Operator::Minus, lit(1_i64)).alias(ROW_ID_COL_NAME),
    );
    joined
        .select(final_exprs)
        .expect("join row_id projection should succeed")
}

pub fn build_partial_output_dataframe(
    left_df: DataFrame,
    right_df: DataFrame,
    join: &Join,
    mode: JoinMode,
) -> DataFrame {
    // In partial mode, keep FK-side rows (including inactive ones) and attach PK-side
    // columns via LEFT JOIN. This guarantees PK materialized columns share FK log-size.
    let fk_is_left = matches!(mode, JoinMode::MANY_TO_ONE);

    let (fk_df_raw, pk_df_raw) = if fk_is_left {
        (left_df, right_df)
    } else {
        (right_df, left_df)
    };

    let prepare_fk_input = |df: DataFrame| {
        let mut projection_exprs = Vec::new();
        for (qualifier, field) in df.schema().iter() {
            if field.name() == ROW_ID_COL_NAME {
                projection_exprs.push(
                    Expr::Column(Column::new(qualifier.cloned(), ROW_ID_COL_NAME))
                        .alias("__fk_row_id__"),
                );
                continue;
            }
            if field.name() == ACTIVATOR_COL_NAME {
                projection_exprs.push(
                    Expr::Column(Column::new(qualifier.cloned(), ACTIVATOR_COL_NAME))
                        .alias("__fk_activator__"),
                );
                continue;
            }
            projection_exprs.push(Expr::Column(Column::new(qualifier.cloned(), field.name())));
        }
        df.select(projection_exprs)
            .expect("partial join fk projection should succeed")
    };

    let prepare_pk_input = |df: DataFrame| {
        let df = df
            .filter(col(ACTIVATOR_COL_NAME).eq(lit(true)))
            .expect("partial join pk activator filter should succeed");
        let mut projection_exprs = Vec::new();
        // Marker to detect whether LEFT JOIN found a PK-side match for each FK row.
        projection_exprs.push(lit(true).alias("__pk_present__"));
        for (qualifier, field) in df.schema().iter() {
            if field.name() == ACTIVATOR_COL_NAME || field.name() == ROW_ID_COL_NAME {
                continue;
            }
            projection_exprs.push(Expr::Column(Column::new(qualifier.cloned(), field.name())));
        }
        df.select(projection_exprs)
            .expect("partial join pk projection should succeed")
    };

    let fk_df = prepare_fk_input(fk_df_raw);
    let pk_df = prepare_pk_input(pk_df_raw);

    let mut join_exprs: Vec<Expr> = join
        .on
        .iter()
        .map(|(left_expr, right_expr)| {
            if fk_is_left {
                left_expr.clone().eq(right_expr.clone())
            } else {
                right_expr.clone().eq(left_expr.clone())
            }
        })
        .collect();
    if let Some(filter) = &join.filter {
        join_exprs.push(filter.clone());
    }

    let joined = fk_df
        .join_on(pk_df, JoinType::Left, join_exprs)
        .expect("partial join should succeed");

    // HasOne modes guarantee at most one PK match per FK row, so we keep the
    // raw LEFT JOIN output and avoid an expensive per-row-id window ranking.
    let joined = joined;

    // Keep partial-join output in FK row-id order so materialized PK columns and
    // FK-side virtual columns stay index-aligned when virtual witness columns are
    // copied from the FK input payload.
    let joined = joined
        .sort(vec![col("__fk_row_id__").sort(true, true)])
        .expect("partial join fk row-id sort should succeed");

    let mut data_exprs = Vec::new();
    let mut fk_row_id = None;
    let mut fk_activator = None;
    let mut pk_present = None;
    for (qualifier, field) in joined.schema().iter() {
        if field.name() == "__fk_row_id__" {
            fk_row_id = Some(Expr::Column(Column::new(qualifier.cloned(), field.name())));
            continue;
        }
        if field.name() == "__fk_activator__" {
            fk_activator = Some(Expr::Column(Column::new(qualifier.cloned(), field.name())));
            continue;
        }
        if field.name() == "__pk_present__" {
            pk_present = Some(Expr::Column(Column::new(qualifier.cloned(), field.name())));
            continue;
        }
        if field.name() == ACTIVATOR_COL_NAME || field.name() == ROW_ID_COL_NAME {
            continue;
        }
        data_exprs.push(Expr::Column(Column::new(qualifier.cloned(), field.name())));
    }

    let fk_activator = fk_activator.expect("partial join output missing fk activator");
    let pk_present = pk_present.expect("partial join output missing pk marker");
    // INNER-join semantics over FK domain: a row is active iff FK row is active and
    // a PK-side match exists for that FK row.
    let output_activator = fk_activator.and(pk_present.is_not_null());

    let mut projection_exprs = data_exprs;
    projection_exprs.push(output_activator.alias(ACTIVATOR_COL_NAME));
    projection_exprs.push(
        fk_row_id
            .expect("partial join output missing fk row_id")
            .alias(ROW_ID_COL_NAME),
    );

    joined
        .select(projection_exprs)
        .expect("partial join output projection should succeed")
}

#[cfg(test)]
mod tests {
    use super::build_output_dataframe;
    use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
    use datafusion::arrow::{
        array::{BooleanArray, Int32Array, Int64Array},
        compute::concat_batches,
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    };
    use datafusion::prelude::SessionContext;
    use datafusion_common::{Column, TableReference};
    use datafusion_expr::{Expr, JoinType, LogicalPlan};
    use std::sync::Arc;

    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct OutputRow {
        row_id: i64,
        left_key: i32,
        left_val: i32,
        right_key: i32,
        right_val: i32,
        activator: bool,
    }

    // Helper: build dataframes, construct a Join plan, run build_output_dataframe,
    // and return the output rows plus the column names for schema checks.
    async fn run_join_case(
        left_rows: &[(i64, i32, i32, bool)],
        right_rows: &[(i64, i32, i32, bool)],
        join_type: JoinType,
    ) -> (Vec<OutputRow>, Vec<String>) {
        let ctx = SessionContext::new();

        let build_df = |rows: &[(i64, i32, i32, bool)],
                        alias: &str,
                        key_col: &str,
                        val_col: &str|
         -> datafusion_common::Result<datafusion::prelude::DataFrame> {
            let row_ids: Vec<i64> = rows.iter().map(|(row_id, _, _, _)| *row_id).collect();
            let keys: Vec<i32> = rows.iter().map(|(_, key, _, _)| *key).collect();
            let vals: Vec<i32> = rows.iter().map(|(_, _, val, _)| *val).collect();
            let acts: Vec<bool> = rows.iter().map(|(_, _, _, act)| *act).collect();
            let schema = Arc::new(Schema::new(vec![
                Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
                Field::new(key_col, DataType::Int32, false),
                Field::new(val_col, DataType::Int32, false),
                Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
            ]));
            let batch = RecordBatch::try_new(
                Arc::clone(&schema),
                vec![
                    Arc::new(Int64Array::from(row_ids)),
                    Arc::new(Int32Array::from(keys)),
                    Arc::new(Int32Array::from(vals)),
                    Arc::new(BooleanArray::from(acts)),
                ],
            )?;
            ctx.read_batch(batch)?.alias(alias)
        };

        let left_df = build_df(left_rows, "l", "l_key", "l_val").unwrap();
        let right_df = build_df(right_rows, "r", "r_key", "r_val").unwrap();

        let left_key = Expr::Column(Column::new(Some(TableReference::bare("l")), "l_key"));
        let right_key = Expr::Column(Column::new(Some(TableReference::bare("r")), "r_key"));
        let join_df = left_df
            .clone()
            .join_on(right_df.clone(), join_type, vec![left_key.eq(right_key)])
            .expect("join should succeed");

        let join = match join_df.logical_plan() {
            LogicalPlan::Join(join) => join.clone(),
            _ => panic!("expected a join logical plan"),
        };

        let output = build_output_dataframe(left_df, right_df, &join);
        let batches = output
            .clone()
            .collect()
            .await
            .expect("collect should succeed");
        let field_names: Vec<String> = output
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().to_string())
            .collect();

        if batches.is_empty() {
            return (Vec::new(), field_names);
        }

        let combined =
            concat_batches(&batches[0].schema(), &batches).expect("concat should succeed");
        let row_id_col = combined
            .column_by_name(ROW_ID_COL_NAME)
            .expect("row_id should exist")
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("row_id should be i64");
        let left_key_col = combined
            .column_by_name("l_key")
            .expect("left key should exist")
            .as_any()
            .downcast_ref::<Int32Array>()
            .expect("left key should be i32");
        let left_val_col = combined
            .column_by_name("l_val")
            .expect("left val should exist")
            .as_any()
            .downcast_ref::<Int32Array>()
            .expect("left val should be i32");
        let right_key_col = combined
            .column_by_name("r_key")
            .expect("right key should exist")
            .as_any()
            .downcast_ref::<Int32Array>()
            .expect("right key should be i32");
        let right_val_col = combined
            .column_by_name("r_val")
            .expect("right val should exist")
            .as_any()
            .downcast_ref::<Int32Array>()
            .expect("right val should be i32");
        let activator_col = combined
            .column_by_name(ACTIVATOR_COL_NAME)
            .expect("activator should exist")
            .as_any()
            .downcast_ref::<BooleanArray>()
            .expect("activator should be bool");

        let mut rows = Vec::new();
        for idx in 0..combined.num_rows() {
            rows.push(OutputRow {
                row_id: row_id_col.value(idx),
                left_key: left_key_col.value(idx),
                left_val: left_val_col.value(idx),
                right_key: right_key_col.value(idx),
                right_val: right_val_col.value(idx),
                activator: activator_col.value(idx),
            });
        }

        (rows, field_names)
    }

    #[tokio::test]
    async fn join_basic_inner_match() {
        // Scenario: one-to-one inner join.
        // Inputs:
        // - left row:  (row_id=1,  l_key=10, l_val=100, activator=true)
        // - right row: (row_id=7, r_key=10, r_val=200, activator=true)
        // Join on l_key == r_key, so the single output row contains:
        // - data columns: l_key=10, l_val=100, r_key=10, r_val=200
        // - row_id: 0 (first row after sorting by left/right row_id)
        // - activator: true
        let left_rows = vec![(1, 10, 100, true)];
        let right_rows = vec![(7, 10, 200, true)];
        let (mut rows, fields) = run_join_case(&left_rows, &right_rows, JoinType::Inner).await;
        rows.sort();

        assert_eq!(
            rows,
            vec![OutputRow {
                row_id: 0,
                left_key: 10,
                left_val: 100,
                right_key: 10,
                right_val: 200,
                activator: true,
            }]
        );
        assert!(!fields.iter().any(|name| name == "__left_row_id__"));
        assert!(!fields.iter().any(|name| name == "__right_row_id__"));
    }

    #[tokio::test]
    async fn join_cartesian_for_duplicate_keys() {
        // Scenario: duplicate join keys on both sides.
        // Inputs:
        // - left rows:  (row_id=0, l_key=1, l_val=10, activator=true)
        //               (row_id=1, l_key=1, l_val=11, activator=true)
        // - right rows: (row_id=5, r_key=1, r_val=20, activator=true)
        //               (row_id=6, r_key=1, r_val=21, activator=true)
        // Join on l_key == r_key, so we get a 2x2 Cartesian product (4 rows):
        // - row_id: 0, 1, 2, 3 in sorted (left_row_id, right_row_id) order
        // - data columns: l_* from the chosen left row and r_* from the chosen right row
        // - activator: true for all real rows
        let left_rows = vec![(0, 1, 10, true), (1, 1, 11, true)];
        let right_rows = vec![(5, 1, 20, true), (6, 1, 21, true)];
        let (mut rows, _) = run_join_case(&left_rows, &right_rows, JoinType::Inner).await;
        rows.sort();

        let expected = vec![
            OutputRow {
                row_id: 0,
                left_key: 1,
                left_val: 10,
                right_key: 1,
                right_val: 20,
                activator: true,
            },
            OutputRow {
                row_id: 1,
                left_key: 1,
                left_val: 10,
                right_key: 1,
                right_val: 21,
                activator: true,
            },
            OutputRow {
                row_id: 2,
                left_key: 1,
                left_val: 11,
                right_key: 1,
                right_val: 20,
                activator: true,
            },
            OutputRow {
                row_id: 3,
                left_key: 1,
                left_val: 11,
                right_key: 1,
                right_val: 21,
                activator: true,
            },
        ];
        assert_eq!(rows, expected);
    }

    #[tokio::test]
    async fn join_mixed_keys_with_missing_matches() {
        // Scenario: larger input with mixed keys; only matching keys appear in the output.
        // Inputs:
        // - left rows:  (row_id=2, l_key=1, l_val=100, activator=true)
        //               (row_id=5, l_key=2, l_val=101, activator=true)
        //               (row_id=7, l_key=3, l_val=102, activator=true)
        //               (row_id=9, l_key=4, l_val=103, activator=true)
        // - right rows: (row_id=1, r_key=2, r_val=200, activator=true)
        //               (row_id=3, r_key=3, r_val=201, activator=true)
        //               (row_id=4, r_key=3, r_val=202, activator=true)
        //               (row_id=8, r_key=5, r_val=203, activator=true)
        // Join on l_key == r_key. Matches:
        // - l_key=2 joins with r_key=2 (row_id 5|1)
        // - l_key=3 joins with r_key=3 (row_id 7|3 and 7|4)
        // Output is sorted by (left_row_id, right_row_id) and row_id is 0,1,2.
        let left_rows = vec![
            (2, 1, 100, true),
            (5, 2, 101, true),
            (7, 3, 102, true),
            (9, 4, 103, true),
        ];
        let right_rows = vec![
            (1, 2, 200, true),
            (3, 3, 201, true),
            (4, 3, 202, true),
            (8, 5, 203, true),
        ];
        let (rows, _) = run_join_case(&left_rows, &right_rows, JoinType::Inner).await;

        let expected = vec![
            OutputRow {
                row_id: 0,
                left_key: 2,
                left_val: 101,
                right_key: 2,
                right_val: 200,
                activator: true,
            },
            OutputRow {
                row_id: 1,
                left_key: 3,
                left_val: 102,
                right_key: 3,
                right_val: 201,
                activator: true,
            },
            OutputRow {
                row_id: 2,
                left_key: 3,
                left_val: 102,
                right_key: 3,
                right_val: 202,
                activator: true,
            },
        ];
        assert_eq!(rows, expected);
    }

    #[tokio::test]
    async fn join_no_matches_returns_empty() {
        // Scenario: no matching keys; output has the right schema but zero rows.
        let left_rows = vec![(1, 1, 10, true)];
        let right_rows = vec![(2, 2, 20, true)];
        let (rows, fields) = run_join_case(&left_rows, &right_rows, JoinType::Inner).await;

        assert!(rows.is_empty());
        assert!(fields.iter().any(|name| name == ROW_ID_COL_NAME));
        assert!(fields.iter().any(|name| name == ACTIVATOR_COL_NAME));
    }
}

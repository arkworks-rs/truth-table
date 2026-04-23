use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use datafusion::functions_window::expr_fn::row_number;
use datafusion::prelude::DataFrame;
use datafusion_common::Column;
use datafusion_expr::{
    Aggregate, Expr, ExprFunctionExt, JoinType, col, expr::Sort as SortExpr, expr_fn::when, lit,
};
/// Expand an aggregate so that:
/// - only active rows contribute to the aggregate
/// - all rows keep their row-level detail, with aggregate values duplicated
/// - exactly one active row per group is marked as the representative (activator = true)
/// - all other rows (including originally inactive ones) have activator = false
pub(super) fn build_output_dataframe(input: &DataFrame, aggregate: &Aggregate) -> DataFrame {
    let row_id_sort_exprs: Vec<SortExpr> = input
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            if field.name() != ROW_ID_COL_NAME {
                return None;
            }
            Some(Expr::Column(Column::new(qualifier.cloned(), ROW_ID_COL_NAME)).sort(true, true))
        })
        .collect();

    // 0. Make the original activator explicit so we don’t lose it
    let df = input
        .clone()
        .with_column_renamed(ACTIVATOR_COL_NAME, "__activator_orig__")
        .unwrap();

    // 1. Aggregate only over active rows
    let active_df = df.clone().filter(col("__activator_orig__")).unwrap();
    // 2. Join aggregates back to *all* rows.
    //
    // For simplicity, assume group_exprs are plain column refs,
    // e.g. vec![col("group_col1"), col("group_col2")].
    // Then we can extract the column names for the join:
    let group_cols: Vec<String> = aggregate
        .group_expr
        .iter()
        .map(|e| match e {
            Expr::Column(c) => c.name.clone(),
            _ => panic!("Non-column group exprs require a pre-aggregate step"),
        })
        .collect();
    let agg_df = active_df
        .clone()
        .aggregate(aggregate.group_expr.clone(), aggregate.aggr_expr.clone())
        .unwrap();
    let agg_group_cols: Vec<String> = group_cols
        .iter()
        .enumerate()
        .map(|(idx, name)| format!("__agg_group_{idx}_{name}"))
        .collect();
    let mut renamed_agg_df = agg_df;
    for (original, renamed) in group_cols.iter().zip(agg_group_cols.iter()) {
        renamed_agg_df = renamed_agg_df
            .with_column_renamed(original, renamed)
            .unwrap();
    }

    let group_cols_str: Vec<&str> = group_cols.iter().map(|s| s.as_str()).collect();
    let agg_group_cols_str: Vec<&str> = agg_group_cols.iter().map(|s| s.as_str()).collect();
    let joined = df
        .join(
            renamed_agg_df,
            JoinType::Left,
            &group_cols_str,
            &agg_group_cols_str,
            None,
        )
        .unwrap();

    // 3. Use a window function to pick a group representative
    //
    // We want: “first active row in each group” to keep activator = true.
    // Others become false.
    //
    // row_number() OVER (PARTITION BY group_exprs ORDER BY nothing)
    // and then:
    //   new_activator = (orig_activator && row_number == 1)
    let mut row_number_builder = row_number().partition_by(aggregate.group_expr.clone());
    let mut row_number_sort_exprs = vec![col("__activator_orig__").sort(false, true)];
    if !row_id_sort_exprs.is_empty() {
        row_number_sort_exprs.extend(row_id_sort_exprs.clone());
    }
    row_number_builder = row_number_builder.order_by(row_number_sort_exprs);
    let window_expr = row_number_builder
        .build()
        .expect("partitioned row_number window should build")
        .alias("__row_number__");
    let with_rownum = joined.window(vec![window_expr]).unwrap();
    // 4. Define the new activator:
    // new __activator__ = __activator_orig__ && __row_number__ == 1

    let new_activator_expr = when(
        col("__activator_orig__").and(col("__row_number__").eq(lit(1_i64))),
        lit(true),
    )
    .otherwise(lit(false))
    .expect("case expression creation should succeed");

    let with_new_activator = with_rownum
        .with_column("__activator__", new_activator_expr)
        .unwrap();
    // To keep deterministic output across executions, order the rows by the
    // grouping columns (if any) and then by the representative flag.
    let mut sort_exprs: Vec<SortExpr> = aggregate
        .group_expr
        .iter()
        .map(|expr| expr.clone().sort(true, true))
        .collect();
    if !row_id_sort_exprs.is_empty() {
        sort_exprs.extend(row_id_sort_exprs);
    }
    sort_exprs.push(col("__row_number__").sort(true, true));
    let sorted = with_new_activator.sort(sort_exprs).unwrap();
    let mut drop_columns: Vec<&str> = agg_group_cols.iter().map(|s| s.as_str()).collect();
    drop_columns.push("__row_number__");
    drop_columns.push("__activator_orig__");
    sorted.drop_columns(&drop_columns).unwrap()
}

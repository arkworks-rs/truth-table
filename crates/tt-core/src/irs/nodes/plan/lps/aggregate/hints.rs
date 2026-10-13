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

    let df = input
        .clone()
        .with_column_renamed(ACTIVATOR_COL_NAME, "__activator_orig__")
        .unwrap();

    let active_df = df.clone().filter(col("__activator_orig__")).unwrap();
    // The aggregates are joined back to all rows on the group columns, so the
    // group expressions must be plain column references.
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

    // The representative of a group is its first row in (active first, row id)
    // order: new activator = orig_activator && row_number == 1.
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

    let new_activator_expr = when(
        col("__activator_orig__").and(col("__row_number__").eq(lit(1_i64))),
        lit(true),
    )
    .otherwise(lit(false))
    .expect("case expression creation should succeed");

    let with_new_activator = with_rownum
        .with_column("__activator__", new_activator_expr)
        .unwrap();
    // Deterministic row order: group columns, then row id, then row number.
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

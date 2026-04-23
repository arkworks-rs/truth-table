use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use datafusion::functions_window::expr_fn::row_number;
use datafusion::prelude::DataFrame;
use datafusion_common::Column;
use datafusion_expr::{
    Expr, ExprFunctionExt, FetchType, Limit, SkipType, col, expr::Sort as SortExpr, expr_fn::when,
    lit,
};

pub(super) fn build_output_dataframe(input: &DataFrame, limit: &Limit) -> DataFrame {
    let input_df = crate::irs::nodes::hints::sort_by_row_id_if_present(input.clone())
        .expect("limit input row-id sort should succeed");

    let skip = match limit.get_skip_type() {
        Ok(SkipType::Literal(skip)) => skip,
        Ok(SkipType::UnsupportedExpr) => {
            panic!("Limit skip must be a literal for proof planning");
        }
        Err(err) => panic!("Limit skip expression error: {err}"),
    };
    let fetch = match limit.get_fetch_type() {
        Ok(FetchType::Literal(fetch)) => fetch,
        Ok(FetchType::UnsupportedExpr) => {
            panic!("Limit fetch must be a literal for proof planning");
        }
        Err(err) => panic!("Limit fetch expression error: {err}"),
    };

    let row_id_sort_exprs: Vec<SortExpr> = input_df
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            if field.name() != ROW_ID_COL_NAME {
                return None;
            }
            Some(Expr::Column(Column::new(qualifier.cloned(), ROW_ID_COL_NAME)).sort(true, true))
        })
        .collect();
    let has_row_id = !row_id_sort_exprs.is_empty();
    let has_activator = input_df
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ACTIVATOR_COL_NAME);

    let df = if has_activator {
        input_df
            .clone()
            .with_column_renamed(ACTIVATOR_COL_NAME, "__activator_orig__")
            .expect("limit should rename activator column")
    } else {
        input_df
            .clone()
            .with_column("__activator_orig__", lit(true))
            .expect("limit should add synthetic activator")
    };

    let mut row_number_builder = row_number().partition_by(vec![col("__activator_orig__")]);
    if has_row_id {
        row_number_builder = row_number_builder.order_by(row_id_sort_exprs);
    }
    let row_number_expr = row_number_builder
        .build()
        .expect("limit row_number window should build")
        .alias("__row_number__");
    let with_row_number = df
        .window(vec![row_number_expr])
        .expect("limit row_number window should apply");

    let start = (skip as i64) + 1;
    let lower = col("__row_number__").gt_eq(lit(start));
    let upper = match fetch {
        Some(fetch) => col("__row_number__").lt_eq(lit((skip + fetch) as i64)),
        None => lit(true),
    };
    let in_range = lower.and(upper);
    let new_activator_expr = when(col("__activator_orig__").and(in_range), lit(true))
        .otherwise(lit(false))
        .expect("limit activator case expression should build");
    let with_new_activator = with_row_number
        .with_column(ACTIVATOR_COL_NAME, new_activator_expr)
        .expect("limit activator update should succeed");

    with_new_activator
        .drop_columns(&["__row_number__", "__activator_orig__"])
        .expect("limit helper columns should be dropped")
}

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

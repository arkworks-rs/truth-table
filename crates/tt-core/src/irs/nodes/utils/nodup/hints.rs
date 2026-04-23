use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME, is_system_column};
use datafusion::functions_window::expr_fn::row_number;
use datafusion::prelude::DataFrame;
use datafusion_common::{Column, Result as DataFusionResult};
use datafusion_expr::{Expr, ExprFunctionExt, SortExpr, col, lit};

pub fn lex_sort_contiguous(df: DataFrame) -> DataFusionResult<DataFrame> {
    let mut order_by: Vec<SortExpr> = Vec::new();
    let mut projection_exprs: Vec<Expr> = Vec::new();
    let mut row_id_col: Option<Column> = None;
    let mut activator_col: Option<Column> = None;

    for (qualifier, field) in df.schema().iter() {
        let col_ref = Column::new(qualifier.cloned(), field.name());
        if field.name() == ROW_ID_COL_NAME {
            row_id_col = Some(col_ref);
            continue;
        }
        if field.name() == ACTIVATOR_COL_NAME {
            activator_col = Some(col_ref.clone());
        }
        projection_exprs.push(Expr::Column(col_ref));
    }

    if let Some(col_ref) = activator_col {
        order_by.push(Expr::Column(col_ref).sort(false, false));
    }
    for expr in projection_exprs.iter() {
        if matches!(expr, Expr::Column(col) if is_system_column(&col.name)) {
            continue;
        }
        order_by.push(expr.clone().sort(false, false));
    }
    if let Some(col_ref) = row_id_col.clone() {
        order_by.push(Expr::Column(col_ref).sort(true, true));
    }

    let row_number_expr = row_number()
        .partition_by(Vec::new())
        .order_by(order_by.clone())
        .build()?
        .alias("__row_number__");
    projection_exprs.push(row_number_expr);
    let with_row_number = df.select(projection_exprs)?;

    let mut final_exprs: Vec<Expr> = with_row_number
        .schema()
        .fields()
        .iter()
        .filter_map(|field| (field.name() != "__row_number__").then_some(col(field.name())))
        .collect();
    final_exprs.push((col("__row_number__") - lit(1_i64)).alias(ROW_ID_COL_NAME));
    let with_row_id = with_row_number.select(final_exprs)?;
    let mut final_order_by: Vec<SortExpr> = Vec::new();
    let schema = with_row_id.schema();
    if schema
        .fields()
        .iter()
        .any(|field| field.name() == ACTIVATOR_COL_NAME)
    {
        let activator_expr = schema
            .iter()
            .find_map(|(qualifier, field)| {
                (field.name() == ACTIVATOR_COL_NAME).then(|| {
                    Expr::Column(Column::new(qualifier.cloned(), field.name())).sort(false, false)
                })
            })
            .expect("activator column should exist");
        final_order_by.push(activator_expr);
    }
    for (qualifier, field) in schema.iter() {
        if is_system_column(field.name()) {
            continue;
        }
        final_order_by
            .push(Expr::Column(Column::new(qualifier.cloned(), field.name())).sort(false, false));
    }
    if schema
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME)
    {
        let row_id_expr = schema
            .iter()
            .find_map(|(qualifier, field)| {
                (field.name() == ROW_ID_COL_NAME).then(|| {
                    Expr::Column(Column::new(qualifier.cloned(), field.name())).sort(true, true)
                })
            })
            .expect("row id column should exist");
        final_order_by.push(row_id_expr);
    }
    with_row_id.sort(final_order_by)
}

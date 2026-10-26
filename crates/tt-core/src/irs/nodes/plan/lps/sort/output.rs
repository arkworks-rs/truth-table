use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use datafusion::arrow::datatypes::DataType;
use datafusion::functions_window::expr_fn::row_number;
use datafusion::prelude::DataFrame;
use datafusion_common::tree_node::{Transformed, TreeNode};
use datafusion_common::{Column, DFSchema};
use datafusion_expr::{
    Expr, ExprFunctionExt, ExprSchemable, Sort, col, expr::Sort as SortExpr, lit,
};

const POSITION_COL: &str = "__sort_position__";

/// Sorts by activator first (active rows first), then the provided sort
/// expressions, and finally `__row_id__` when present for deterministic output.
/// `__row_id__` becomes the row's output position, numbered by a window that
/// requires the sort order: DataFusion keeps an order only where an operator
/// requires it, so nodes above this one order their hints by `__row_id__`.
pub(crate) fn sort_df(input: &DataFrame, sort: &Sort) -> DataFrame {
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

    let mut sort_exprs: Vec<SortExpr> = Vec::with_capacity(sort.expr.len() + 2);
    sort_exprs.push(col(ACTIVATOR_COL_NAME).sort(false, false));
    let keys = resolve_sort_exprs(input.schema(), &sort.expr);
    #[cfg(feature = "test-utils")]
    let keys = crate::test_utils::dishonest_prover::forge_sort_exprs(keys);
    sort_exprs.extend(keys);
    sort_exprs.extend(row_id_sort_exprs);

    let sorted = input
        .clone()
        .sort(sort_exprs.clone())
        .expect("sorting activated rows should succeed");
    let sorted = match sort.fetch {
        Some(fetch) => sorted
            // DataFusion encodes top-k as `Sort(fetch = k)`; apply it so the
            // proof-side plan output matches the compact query result.
            .limit(0, Some(fetch))
            .expect("top-k after sorting should succeed"),
        None => sorted,
    };

    let position = row_number()
        .order_by(sort_exprs)
        .build()
        .expect("sort position window should build")
        .alias(POSITION_COL);
    let numbered = sorted
        .window(vec![position])
        .expect("sort position window should apply");
    let mut exprs: Vec<Expr> = numbered
        .schema()
        .iter()
        .filter(|(_, field)| field.name() != ROW_ID_COL_NAME && field.name() != POSITION_COL)
        .map(|(qualifier, field)| Expr::Column(Column::new(qualifier.cloned(), field.name())))
        .collect();
    exprs.push(
        (col(POSITION_COL) - lit(1u64))
            .cast_to(&DataType::Int64, numbered.schema())
            .expect("sort position cast should succeed")
            .alias(ROW_ID_COL_NAME),
    );
    numbered
        .select(exprs)
        .expect("sort output projection should succeed")
}

pub(crate) fn resolve_sort_exprs(schema: &DFSchema, exprs: &[SortExpr]) -> Vec<SortExpr> {
    exprs
        .iter()
        .map(|sort_expr| SortExpr {
            expr: resolve_sort_expr(schema, sort_expr.expr.clone()),
            asc: sort_expr.asc,
            nulls_first: sort_expr.nulls_first,
        })
        .collect()
}

fn resolve_sort_expr(schema: &DFSchema, expr: Expr) -> Expr {
    expr.transform(|inner| {
        if let Expr::Column(col) = &inner {
            let name = col.name();
            if let Some(relation) = col.relation.as_ref() {
                let has_exact = schema.iter().any(|(qualifier, field)| {
                    field.name() == name && qualifier.as_ref() == Some(&relation)
                });
                if has_exact {
                    return Ok(Transformed::no(inner));
                }
            }

            if let Some((qualifier, _)) = schema.iter().find(|(_, field)| field.name() == name) {
                return Ok(Transformed::yes(Expr::Column(Column::new(
                    qualifier.cloned(),
                    name,
                ))));
            }

            return Ok(Transformed::yes(Expr::Column(Column::new_unqualified(
                name,
            ))));
        }

        Ok(Transformed::no(inner))
    })
    .unwrap()
    .data
}

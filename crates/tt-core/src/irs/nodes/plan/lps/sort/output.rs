use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use datafusion::prelude::DataFrame;
use datafusion_common::tree_node::{Transformed, TreeNode};
use datafusion_common::{Column, DFSchema};
use datafusion_expr::{Expr, Sort, col, expr::Sort as SortExpr};

/// Sorts by activator first (active rows first), then the provided sort
/// expressions, and finally `__row_id__` when present for deterministic output.
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

    // Prefix sort with activator so active rows come first.
    let mut sort_exprs: Vec<SortExpr> = Vec::with_capacity(sort.expr.len() + 2);
    sort_exprs.push(col(ACTIVATOR_COL_NAME).sort(false, false));
    // Apply the sort expressions requested by the query.
    sort_exprs.extend(resolve_sort_exprs(input.schema(), &sort.expr));
    if !row_id_sort_exprs.is_empty() {
        // Stabilize ordering for identical sort keys.
        sort_exprs.extend(row_id_sort_exprs);
    }

    let sorted = input
        .clone()
        .sort(sort_exprs)
        .expect("sorting activated rows should succeed");

    match sort.fetch {
        Some(fetch) => sorted
            // DataFusion encodes top-k as `Sort(fetch = k)`. Respect that here
            // so the proof-side plan output matches the compact query result.
            .limit(0, Some(fetch))
            .expect("top-k after sorting should succeed"),
        None => sorted,
    }
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

use arithmetic::ACTIVATOR_COL_NAME;
use datafusion::prelude::DataFrame;
use datafusion_common::Column;
use datafusion_expr::{Expr, Filter};

/// Build a DataFrame that preserves all rows but deactivates ones that do not
/// satisfy the filter predicate by zeroing the activator column.
pub(super) fn build_output_dataframe(input: &DataFrame, filter: &Filter) -> DataFrame {
    let predicate = filter.predicate.clone();
    let mut projection_exprs: Vec<Expr> = Vec::new();
    let mut activator_exprs: Vec<Expr> = Vec::new();
    let mut activator_insert_pos: Option<usize> = None;

    // Build a projection that keeps every non-activator column and records where
    // the activator should be reinserted after it is recomputed.
    for (qualifier, field) in input.schema().iter() {
        let name = field.name();
        if name == ACTIVATOR_COL_NAME {
            if activator_insert_pos.is_none() {
                activator_insert_pos = Some(projection_exprs.len());
            }
            activator_exprs.push(Expr::Column(Column::new(qualifier.cloned(), name)));
            continue;
        }
        projection_exprs.push(Expr::Column(Column::new(qualifier.cloned(), name)));
    }

    // The new activator is the AND of every input activator and the predicate,
    // placed where the first input activator was.
    if !activator_exprs.is_empty() {
        let mut combined = activator_exprs[0].clone();
        for expr in activator_exprs.iter().skip(1) {
            combined = combined.and(expr.clone());
        }
        combined = combined.and(predicate).alias(ACTIVATOR_COL_NAME);
        let insert_pos = activator_insert_pos.unwrap_or(projection_exprs.len());
        projection_exprs.insert(insert_pos, combined);
    }

    input
        .clone()
        .select(projection_exprs)
        .expect("filter application should succeed")
}

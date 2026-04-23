use datafusion::prelude::DataFrame;
use datafusion_common::tree_node::{Transformed, TreeNode};
use datafusion_common::{Column, DFSchema};
use datafusion_expr::Projection;

pub(super) fn build_output_dataframe(input: &DataFrame, projection: &Projection) -> DataFrame {
    let input_df = crate::irs::nodes::hints::sort_by_row_id_if_present(input.clone())
        .expect("projection row-id sort should succeed");
    let mut projection_exprs = projection
        .expr
        .iter()
        .map(|expr| resolve_projection_expr(input_df.schema(), expr.clone()))
        .collect::<Vec<_>>();
    crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut projection_exprs);
    crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut projection_exprs);
    input_df
        .select(projection_exprs)
        .expect("projection application should succeed")
}

/// Verifier-side variant that avoids extra normalization work when possible.
/// Falls back to the prover-style builder if direct projection resolution fails.
pub(super) fn build_output_dataframe_for_verifier(
    input: &DataFrame,
    projection: &Projection,
) -> DataFrame {
    let mut projection_exprs = projection.expr.clone();
    crate::irs::nodes::hints::append_activator_exprs_if_present(input, &mut projection_exprs);
    crate::irs::nodes::hints::append_row_id_expr_if_present(input, &mut projection_exprs);
    match input.clone().select(projection_exprs) {
        Ok(df) => df,
        Err(_) => build_output_dataframe(input, projection),
    }
}

fn resolve_projection_expr(
    schema: &DFSchema,
    expr: datafusion_expr::Expr,
) -> datafusion_expr::Expr {
    expr.transform(|inner| {
        if let datafusion_expr::Expr::Column(col) = &inner {
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
                return Ok(Transformed::yes(datafusion_expr::Expr::Column(
                    Column::new(qualifier.cloned(), name),
                )));
            }

            return Ok(Transformed::yes(datafusion_expr::Expr::Column(
                Column::new_unqualified(name),
            )));
        }

        Ok(Transformed::no(inner))
    })
    .unwrap()
    .data
}

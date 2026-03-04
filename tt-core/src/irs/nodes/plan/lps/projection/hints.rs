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

#[cfg(test)]
mod tests {
    use super::build_output_dataframe;
    use arithmetic::ACTIVATOR_COL_NAME;
    use datafusion::arrow::{
        array::{ArrayRef, BooleanArray, Date32Array, Int32Array},
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    };
    use datafusion::prelude::SessionContext;
    use datafusion_common::{ScalarValue, TableReference};
    use datafusion_expr::{
        Expr, Operator, Projection, col,
        expr::{Alias, BinaryExpr},
    };
    use std::sync::Arc;

    async fn run_projection_test(
        ctx: &SessionContext,
        input_columns: &[(Field, ArrayRef)],
        exprs: &[Expr],
        expected_columns: &[(Field, ArrayRef)],
    ) {
        let input_schema = Arc::new(Schema::new(
            input_columns
                .iter()
                .map(|(field, _)| field.clone())
                .collect::<Vec<_>>(),
        ));
        let input_batch = RecordBatch::try_new(
            Arc::clone(&input_schema),
            input_columns
                .iter()
                .map(|(_, array)| Arc::clone(array))
                .collect(),
        )
        .expect("input batch construction should succeed");
        let input_df = ctx
            .read_batch(input_batch)
            .expect("failed to read batch into DataFrame");
        let projection =
            Projection::try_new(exprs.to_vec(), Arc::new(input_df.logical_plan().clone()))
                .expect("projection creation should succeed");
        let projected = build_output_dataframe(&input_df, &projection);
        let batches = projected.collect().await.unwrap();
        let expected_schema = Arc::new(Schema::new(
            expected_columns
                .iter()
                .map(|(field, _)| field.clone())
                .collect::<Vec<_>>(),
        ));
        let expected_batch = RecordBatch::try_new(
            expected_schema,
            expected_columns
                .iter()
                .map(|(_, array)| Arc::clone(array))
                .collect(),
        )
        .expect("expected batch construction should succeed");
        assert_eq!(batches, vec![expected_batch]);
    }

    #[tokio::test]
    async fn projection_node_output_is_correct() {
        let ctx = SessionContext::new();

        run_projection_test(
            &ctx,
            &[
                (
                    Field::new("val1", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![1, 2, 3, 4])),
                ),
                (
                    Field::new("val2", DataType::Date32, false),
                    Arc::new(Date32Array::from(vec![18628, 18629, 18630, 18631])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, false, true, true])),
                ),
            ],
            &[Expr::Alias(Alias::new(
                col("val2"),
                None::<TableReference>,
                "projected_val2",
            ))],
            &[
                (
                    Field::new("projected_val2", DataType::Date32, false),
                    Arc::new(Date32Array::from(vec![18628, 18629, 18630, 18631])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, false, true, true])),
                ),
            ],
        )
        .await;

        run_projection_test(
            &ctx,
            &[
                (
                    Field::new("val1", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![1, 2, 3, 4])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, false, true, true])),
                ),
            ],
            &[Expr::Alias(Alias::new(
                Expr::BinaryExpr(BinaryExpr::new(
                    Box::new(col("val1")),
                    Operator::Plus,
                    Box::new(Expr::Literal(ScalarValue::Int32(Some(2)))),
                )),
                None::<TableReference>,
                "val1_plus_two",
            ))],
            &[
                (
                    Field::new("val1_plus_two", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![3, 4, 5, 6])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, false, true, true])),
                ),
            ],
        )
        .await;
    }
}

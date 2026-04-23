use arithmetic::ACTIVATOR_COL_NAME;
use datafusion::arrow::array::ArrayRef;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::prelude::DataFrame;
use datafusion_common::tree_node::{Transformed, TreeNode};
use datafusion_common::{Column, Result as DataFusionResult, ScalarValue};
use datafusion_expr::expr::InList;
use datafusion_expr::{Expr, Filter, lit};
use tokio::runtime::RuntimeFlavor;

/// Build a DataFrame that preserves all rows but deactivates ones that do not
/// satisfy the filter predicate by zeroing the activator column.
pub(super) fn build_output_dataframe(input: &DataFrame, filter: &Filter) -> DataFrame {
    fn collect_blocking(df: DataFrame) -> DataFusionResult<Vec<RecordBatch>> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => match handle.runtime_flavor() {
                RuntimeFlavor::MultiThread => {
                    tokio::task::block_in_place(|| handle.block_on(df.collect()))
                }
                RuntimeFlavor::CurrentThread => {
                    let handle = handle.clone();
                    std::thread::spawn(move || handle.block_on(df.collect()))
                        .join()
                        .unwrap()
                }
                _ => handle.block_on(df.collect()),
            },
            Err(_) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(df.collect()),
        }
    }

    fn rewrite_in_subquery(expr: Expr, input: &DataFrame) -> Expr {
        let (session_state, _) = input.clone().into_parts();
        let rewritten = expr
            .transform(|node| {
                if let Expr::InSubquery(in_subquery) = node {
                    if in_subquery.subquery.outer_ref_columns.is_empty() {
                        let plan = in_subquery.subquery.subquery.as_ref().clone();
                        let subquery_df = DataFrame::new(session_state.clone(), plan);
                        let batches =
                            collect_blocking(subquery_df).expect("filter subquery collect");
                        let mut values = Vec::new();
                        for batch in batches.iter() {
                            let array: ArrayRef = batch.column(0).clone();
                            for idx in 0..batch.num_rows() {
                                values.push(
                                    ScalarValue::try_from_array(array.as_ref(), idx)
                                        .expect("filter subquery value"),
                                );
                            }
                        }
                        let replacement = if values.is_empty() {
                            if in_subquery.negated {
                                lit(true)
                            } else {
                                lit(false)
                            }
                        } else {
                            Expr::InList(InList::new(
                                in_subquery.expr.clone(),
                                values.into_iter().map(Expr::Literal).collect(),
                                in_subquery.negated,
                            ))
                        };
                        return Ok(Transformed::yes(replacement));
                    }
                    return Ok(Transformed::no(Expr::InSubquery(in_subquery)));
                }
                Ok(Transformed::no(node))
            })
            .expect("filter predicate rewrite should succeed");
        rewritten.data
    }

    let predicate = rewrite_in_subquery(filter.predicate.clone(), input);
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

    // If the input has an activator, combine all activators with the filter predicate
    // and insert the new activator back into the projected column order.
    if !activator_exprs.is_empty() {
        let mut combined = activator_exprs[0].clone();
        for expr in activator_exprs.iter().skip(1) {
            combined = combined.and(expr.clone());
        }
        combined = combined.and(predicate).alias(ACTIVATOR_COL_NAME);
        let insert_pos = activator_insert_pos.unwrap_or(projection_exprs.len());
        projection_exprs.insert(insert_pos, combined);
    }

    // Apply the projection so all rows remain, but activator marks filtered-out rows.
    input
        .clone()
        .select(projection_exprs)
        .expect("filter application should succeed")
}

use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use datafusion::arrow::{compute::concat_batches, record_batch::RecordBatch};
use datafusion::functions_window::expr_fn::row_number;
use datafusion::prelude::{DataFrame, SessionContext};
use datafusion_common::{Column, DataFusionError, Result as DataFusionResult, ScalarValue};
use datafusion_expr::{col, lit, Expr, ExprFunctionExt, Join};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::runtime::RuntimeFlavor;

use super::{SRC_LEFT_COL_NAME, SRC_RIGHT_COL_NAME};

struct IndexedJoinFrames {
    output_left: DataFrame,
    output_right: DataFrame,
    src_left: DataFrame,
    src_right: DataFrame,
    nodup_input: DataFrame,
}

#[cfg(test)]
pub(crate) fn build_source_dfs(
    left: DataFrame,
    right: DataFrame,
    _output: DataFrame,
    join: &Join,
) -> DataFusionResult<(DataFrame, DataFrame)> {
    let frames = build_indexed_join_frames(left, right, join)?;
    Ok((frames.src_left, frames.src_right))
}

pub(crate) fn build_output_and_source_dfs(
    left: DataFrame,
    right: DataFrame,
    join: &Join,
) -> DataFusionResult<(DataFrame, DataFrame, DataFrame, DataFrame, DataFrame)> {
    let frames = build_indexed_join_frames(left, right, join)?;
    Ok((
        frames.output_left,
        frames.output_right,
        frames.src_left,
        frames.src_right,
        frames.nodup_input,
    ))
}

fn build_indexed_join_frames(
    left: DataFrame,
    right: DataFrame,
    join: &Join,
) -> DataFusionResult<IndexedJoinFrames> {
    // Prefer aliased row ids to avoid `__row_id__` collisions after optimizer
    // rewrites (e.g. scalar-subquery joins). Fall back only when DataFusion still
    // reports an ambiguity on this version.
    build_indexed_join_frames_impl(left.clone(), right.clone(), join, true).or_else(|err| {
        if should_retry_source_mapping_without_aliased_row_ids(&err) {
            build_indexed_join_frames_impl(left, right, join, false)
        } else {
            Err(err)
        }
    })
}

fn build_indexed_join_frames_impl(
    left: DataFrame,
    right: DataFrame,
    join: &Join,
    aliased_row_ids: bool,
) -> DataFusionResult<IndexedJoinFrames> {
    // Build join predicates (equi-join pairs plus optional filter).
    let mut join_exprs: Vec<Expr> = join
        .on
        .iter()
        .map(|(left_expr, right_expr)| left_expr.clone().eq(right_expr.clone()))
        .collect();
    for expr in join.on.iter().flat_map(|(l, r)| [l, r]) {
        if expr_has_system_column(expr) {
            return Err(DataFusionError::Plan(
                "Join keys must not reference system columns".to_string(),
            ));
        }
    }
    if let Some(filter) = &join.filter {
        if expr_has_system_column(filter) {
            return Err(DataFusionError::Plan(
                "Join filters must not reference system columns".to_string(),
            ));
        }
        join_exprs.push(filter.clone());
    }

    let (left, left_row_id) = if aliased_row_ids {
        prepare_input_aliased(left, "left", "tt_src_left_row_id")?
    } else {
        prepare_input(left, "left", "tt_src_left_row_id")?
    };
    let (right, right_row_id) = if aliased_row_ids {
        prepare_input_aliased(right, "right", "tt_src_right_row_id")?
    } else {
        prepare_input(right, "right", "tt_src_right_row_id")?
    };
    let left_payload_templates =
        payload_template_columns(&left, left_row_id.name.as_str())?;
    let right_payload_templates =
        payload_template_columns(&right, right_row_id.name.as_str())?;

    let joined = left.clone().join_on(right.clone(), join.join_type, join_exprs)?;
    let joined_left_row_id = resolve_column_like(&joined, &left_row_id)?;
    let joined_right_row_id = resolve_column_like(&joined, &right_row_id)?;
    let row_id_sort_exprs = vec![
        Expr::Column(joined_left_row_id.clone()).sort(true, true),
        Expr::Column(joined_right_row_id.clone()).sort(true, true),
    ];
    let sorted = joined.sort(row_id_sort_exprs.clone())?;

    let sorted_left_row_id = resolve_column_like(&sorted, &left_row_id)?;
    let sorted_right_row_id = resolve_column_like(&sorted, &right_row_id)?;
    let sorted_row_id_sort_exprs = vec![
        Expr::Column(sorted_left_row_id.clone()).sort(true, true),
        Expr::Column(sorted_right_row_id.clone()).sort(true, true),
    ];

    let left_payload_exprs = resolve_payload_exprs(&sorted, &left_payload_templates)?;
    let right_payload_exprs = resolve_payload_exprs(&sorted, &right_payload_templates)?;
    let left_indexed_aliases = indexed_aliases("__tt_left_payload", left_payload_exprs.len());
    let right_indexed_aliases = indexed_aliases("__tt_right_payload", right_payload_exprs.len());
    let payload_exprs = left_payload_exprs
        .iter()
        .zip(left_indexed_aliases.iter())
        .map(|(expr, alias)| expr.clone().alias(alias))
        .chain(
            right_payload_exprs
                .iter()
                .zip(right_indexed_aliases.iter())
                .map(|(expr, alias)| expr.clone().alias(alias)),
        )
        .collect::<Vec<_>>();

    let row_number_expr = row_number()
        .partition_by(Vec::new())
        .order_by(sorted_row_id_sort_exprs)
        .build()?
        .alias("__row_number__");
    let indexed = sorted.select({
        let mut exprs = payload_exprs.clone();
        exprs.push(Expr::Column(sorted_left_row_id).alias("__src_left_row_id__"));
        exprs.push(Expr::Column(sorted_right_row_id).alias("__src_right_row_id__"));
        exprs.push(lit(true).alias(ACTIVATOR_COL_NAME));
        exprs.push(row_number_expr);
        exprs
    })?;
    let indexed = materialize_dataframe(indexed)?;

    // Materialize the step-3 output-side lookup bases here so the join gadget
    // does not need to reconstruct left/right payload slices later from the
    // combined output table.
    let output_left = indexed
        .clone()
        .select(with_helper_col(
            left_indexed_aliases
                .iter()
                .map(|alias| col(alias))
                .collect::<Vec<_>>(),
            "__row_number__",
        ))?
        .sort(vec![col("__row_number__").sort(true, true)])?
        .select(with_activator_only(
            left_indexed_aliases
                .iter()
                .map(|alias| col(alias))
                .collect::<Vec<_>>(),
        ))?;
    let output_right = indexed
        .clone()
        .select(with_helper_col(
            right_indexed_aliases
                .iter()
                .map(|alias| col(alias))
                .collect::<Vec<_>>(),
            "__row_number__",
        ))?
        .sort(vec![col("__row_number__").sort(true, true)])?
        .select(with_activator_only(
            right_indexed_aliases
                .iter()
                .map(|alias| col(alias))
                .collect::<Vec<_>>(),
        ))?;

    // Step 3 only needs a valid immediate-parent row id for each output-side
    // payload row. Deriving source ids from the replayed join row ordering is
    // brittle for nested joins, so instead we match the actual output-side
    // payload rows back to the immediate input payload rows directly.
    let src_left = source_ids_from_payload_lookup(
        &output_left,
        &left,
        left_row_id.name.as_str(),
        SRC_LEFT_COL_NAME,
    )?;
    let src_right = source_ids_from_payload_lookup(
        &output_right,
        &right,
        right_row_id.name.as_str(),
        SRC_RIGHT_COL_NAME,
    )?;

    let output_left = append_source_to_output_payload(&output_left, &src_left, SRC_LEFT_COL_NAME)?;
    let output_right =
        append_source_to_output_payload(&output_right, &src_right, SRC_RIGHT_COL_NAME)?;

    let nodup_input = build_nodup_input_from_sources(&src_left, &src_right)?;

    Ok(IndexedJoinFrames {
        output_left,
        output_right,
        src_left,
        src_right,
        nodup_input,
    })
}

fn source_ids_from_payload_lookup(
    output_payload: &DataFrame,
    input_payload: &DataFrame,
    input_row_id_name: &str,
    src_col_name: &str,
) -> DataFusionResult<DataFrame> {
    let output_batches = collect_blocking(output_payload.clone())?;
    let input_batches = collect_blocking(input_payload.clone())?;

    let mut payload_to_source = HashMap::<Vec<ScalarValue>, i64>::new();
    for batch in &input_batches {
        let schema = batch.schema();
        let row_id_idx = schema
            .fields()
            .iter()
            .position(|field| field.name() == input_row_id_name)
            .ok_or_else(|| {
                DataFusionError::Plan(format!(
                    "Join source mapping input is missing {input_row_id_name}"
                ))
            })?;
        let payload_indices = schema
            .fields()
            .iter()
            .enumerate()
            .filter_map(|(idx, field)| {
                (field.name() != ACTIVATOR_COL_NAME && field.name() != input_row_id_name)
                    .then_some(idx)
            })
            .collect::<Vec<_>>();
        for row in 0..batch.num_rows() {
            let payload = payload_indices
                .iter()
                .map(|idx| ScalarValue::try_from_array(batch.column(*idx).as_ref(), row))
                .collect::<DataFusionResult<Vec<_>>>()?;
            let row_id = scalar_i64(
                ScalarValue::try_from_array(batch.column(row_id_idx).as_ref(), row)?,
                input_row_id_name,
            )?;
            payload_to_source
                .entry(payload)
                .and_modify(|existing| {
                    if row_id < *existing {
                        *existing = row_id;
                    }
                })
                .or_insert(row_id);
        }
    }

    let mut src_values = Vec::new();
    let mut output_row_ids = Vec::new();
    for batch in &output_batches {
        let schema = batch.schema();
        let payload_indices = schema
            .fields()
            .iter()
            .enumerate()
            .filter_map(|(idx, field)| (field.name() != ACTIVATOR_COL_NAME).then_some(idx))
            .collect::<Vec<_>>();
        for row in 0..batch.num_rows() {
            let payload = payload_indices
                .iter()
                .map(|idx| ScalarValue::try_from_array(batch.column(*idx).as_ref(), row))
                .collect::<DataFusionResult<Vec<_>>>()?;
            let Some(src_row_id) = payload_to_source.get(&payload).copied() else {
                return Err(DataFusionError::Execution(format!(
                    "Join source mapping could not find a matching input row for {src_col_name}"
                )));
            };
            src_values.push(src_row_id);
            output_row_ids.push(output_row_ids.len() as i64);
        }
    }

    let schema = Arc::new(datafusion::arrow::datatypes::Schema::new(vec![
        datafusion::arrow::datatypes::Field::new(src_col_name, datafusion::arrow::datatypes::DataType::Int64, false),
        datafusion::arrow::datatypes::Field::new(ACTIVATOR_COL_NAME, datafusion::arrow::datatypes::DataType::Boolean, false),
        datafusion::arrow::datatypes::Field::new(ROW_ID_COL_NAME, datafusion::arrow::datatypes::DataType::Int64, false),
    ]));
    let batch = RecordBatch::try_new(
        schema,
        vec![
            Arc::new(datafusion::arrow::array::Int64Array::from(src_values)),
            Arc::new(datafusion::arrow::array::BooleanArray::from(vec![true; output_row_ids.len()])),
            Arc::new(datafusion::arrow::array::Int64Array::from(output_row_ids)),
        ],
    )?;
    SessionContext::new().read_batch(batch)
}

fn build_nodup_input_from_sources(
    src_left: &DataFrame,
    src_right: &DataFrame,
) -> DataFusionResult<DataFrame> {
    let left_batches = collect_blocking(src_left.clone())?;
    let right_batches = collect_blocking(src_right.clone())?;
    let Some(left_first) = left_batches.first() else {
        return SessionContext::new().read_batch(RecordBatch::new_empty(Arc::new(
            datafusion::arrow::datatypes::Schema::new(vec![
                datafusion::arrow::datatypes::Field::new(
                    SRC_LEFT_COL_NAME,
                    datafusion::arrow::datatypes::DataType::Int64,
                    false,
                ),
                datafusion::arrow::datatypes::Field::new(
                    SRC_RIGHT_COL_NAME,
                    datafusion::arrow::datatypes::DataType::Int64,
                    false,
                ),
                datafusion::arrow::datatypes::Field::new(
                    ACTIVATOR_COL_NAME,
                    datafusion::arrow::datatypes::DataType::Boolean,
                    false,
                ),
                datafusion::arrow::datatypes::Field::new(
                    ROW_ID_COL_NAME,
                    datafusion::arrow::datatypes::DataType::Int64,
                    false,
                ),
            ]),
        )));
    };
    let Some(right_first) = right_batches.first() else {
        return Err(DataFusionError::Execution(
            "Join source mapping produced a right source table with no batches".to_string(),
        ));
    };
    let left = concat_batches(&left_first.schema(), left_batches.iter().collect::<Vec<_>>())?;
    let right = concat_batches(&right_first.schema(), right_batches.iter().collect::<Vec<_>>())?;
    if left.num_rows() != right.num_rows() {
        return Err(DataFusionError::Execution(
            "Join source mapping produced left/right source tables of different lengths".to_string(),
        ));
    }
    let left_src_idx = left
        .schema()
        .fields()
        .iter()
        .position(|field| field.name() == SRC_LEFT_COL_NAME)
        .expect("src_left schema should contain src_left");
    let right_src_idx = right
        .schema()
        .fields()
        .iter()
        .position(|field| field.name() == SRC_RIGHT_COL_NAME)
        .expect("src_right schema should contain src_right");
    let row_id_idx = left
        .schema()
        .fields()
        .iter()
        .position(|field| field.name() == ROW_ID_COL_NAME)
        .expect("src_left schema should contain row id");

    let mut src_left_vals = Vec::with_capacity(left.num_rows());
    let mut src_right_vals = Vec::with_capacity(left.num_rows());
    let mut row_ids = Vec::with_capacity(left.num_rows());
    for row in 0..left.num_rows() {
        src_left_vals.push(
            scalar_i64(
                ScalarValue::try_from_array(left.column(left_src_idx).as_ref(), row)?,
                SRC_LEFT_COL_NAME,
            )?,
        );
        src_right_vals.push(
            scalar_i64(
                ScalarValue::try_from_array(right.column(right_src_idx).as_ref(), row)?,
                SRC_RIGHT_COL_NAME,
            )?,
        );
        row_ids.push(
            scalar_i64(
                ScalarValue::try_from_array(left.column(row_id_idx).as_ref(), row)?,
                ROW_ID_COL_NAME,
            )?,
        );
    }

    let schema = Arc::new(datafusion::arrow::datatypes::Schema::new(vec![
        datafusion::arrow::datatypes::Field::new(SRC_LEFT_COL_NAME, datafusion::arrow::datatypes::DataType::Int64, false),
        datafusion::arrow::datatypes::Field::new(SRC_RIGHT_COL_NAME, datafusion::arrow::datatypes::DataType::Int64, false),
        datafusion::arrow::datatypes::Field::new(ACTIVATOR_COL_NAME, datafusion::arrow::datatypes::DataType::Boolean, false),
        datafusion::arrow::datatypes::Field::new(ROW_ID_COL_NAME, datafusion::arrow::datatypes::DataType::Int64, false),
    ]));
    let batch = RecordBatch::try_new(
        schema,
        vec![
            Arc::new(datafusion::arrow::array::Int64Array::from(src_left_vals)),
            Arc::new(datafusion::arrow::array::Int64Array::from(src_right_vals)),
            Arc::new(datafusion::arrow::array::BooleanArray::from(vec![true; row_ids.len()])),
            Arc::new(datafusion::arrow::array::Int64Array::from(row_ids)),
        ],
    )?;
    SessionContext::new().read_batch(batch)
}

fn scalar_i64(value: ScalarValue, col_name: &str) -> DataFusionResult<i64> {
    match value {
        ScalarValue::Int64(Some(v)) => Ok(v),
        _ => Err(DataFusionError::Execution(format!(
            "Join source mapping column {col_name} was not Int64"
        ))),
    }
}

fn append_source_to_output_payload(
    output_payload: &DataFrame,
    src_df: &DataFrame,
    src_col_name: &str,
) -> DataFusionResult<DataFrame> {
    let output_batches = collect_blocking(output_payload.clone())?;
    let src_batches = collect_blocking(src_df.clone())?;
    let Some(output_first) = output_batches.first() else {
        return SessionContext::new().read_batch(RecordBatch::new_empty(Arc::new(
            datafusion::arrow::datatypes::Schema::empty(),
        )));
    };
    let Some(src_first) = src_batches.first() else {
        return Err(DataFusionError::Execution(format!(
            "Join source mapping missing {src_col_name} batches"
        )));
    };
    let output = concat_batches(
        &output_first.schema(),
        output_batches.iter().collect::<Vec<_>>(),
    )?;
    let src = concat_batches(&src_first.schema(), src_batches.iter().collect::<Vec<_>>())?;
    if output.num_rows() != src.num_rows() {
        return Err(DataFusionError::Execution(format!(
            "Join source mapping produced mismatched output/src row counts for {src_col_name}"
        )));
    }
    let src_idx = src
        .schema()
        .fields()
        .iter()
        .position(|field| field.name() == src_col_name)
        .ok_or_else(|| DataFusionError::Execution(format!("missing {src_col_name}")))?;
    let mut fields = output
        .schema()
        .fields()
        .iter()
        .map(|field| field.as_ref().clone())
        .collect::<Vec<_>>();
    fields.push(src.schema().field(src_idx).clone());
    let mut arrays = output.columns().to_vec();
    arrays.push(src.column(src_idx).clone());
    SessionContext::new().read_batch(RecordBatch::try_new(
        Arc::new(datafusion::arrow::datatypes::Schema::new(fields)),
        arrays,
    )?)
}

fn prepare_input(
    df: DataFrame,
    side: &str,
    _row_id_alias: &str,
) -> DataFusionResult<(DataFrame, Column)> {
    let activator_cols: Vec<Column> = df
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            (field.name() == ACTIVATOR_COL_NAME)
                .then_some(Column::new(qualifier.cloned(), ACTIVATOR_COL_NAME))
        })
        .collect();
    if activator_cols.len() > 1 {
        return Err(DataFusionError::Plan(format!(
            "Join {side} input has multiple {ACTIVATOR_COL_NAME} columns"
        )));
    }
    let Some(activator_col) = activator_cols.into_iter().next() else {
        return Err(DataFusionError::Plan(format!(
            "Join {side} input is missing {ACTIVATOR_COL_NAME}"
        )));
    };
    let df = df.filter(Expr::Column(activator_col).eq(lit(true)))?;
    let mut projection_exprs = Vec::new();
    let row_id_cols: Vec<Column> = df
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            if field.name() == ACTIVATOR_COL_NAME {
                return None;
            }
            let col = Column::new(qualifier.cloned(), field.name());
            projection_exprs.push(Expr::Column(col.clone()));
            (field.name() == ROW_ID_COL_NAME)
                .then_some(Column::new(qualifier.cloned(), ROW_ID_COL_NAME))
        })
        .collect();
    if row_id_cols.len() > 1 {
        return Err(DataFusionError::Plan(format!(
            "Join {side} input has multiple {ROW_ID_COL_NAME} columns"
        )));
    }
    let Some(row_id_col) = row_id_cols.into_iter().next() else {
        return Err(DataFusionError::Plan(format!(
            "Join {side} input is missing {ROW_ID_COL_NAME}"
        )));
    };
    let df = df.select(projection_exprs)?;
    Ok((df, row_id_col))
}


fn prepare_input_aliased(
    df: DataFrame,
    side: &str,
    row_id_alias: &str,
) -> DataFusionResult<(DataFrame, Column)> {
    let activator_cols: Vec<Column> = df
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            (field.name() == ACTIVATOR_COL_NAME)
                .then_some(Column::new(qualifier.cloned(), ACTIVATOR_COL_NAME))
        })
        .collect();
    if activator_cols.len() > 1 {
        return Err(DataFusionError::Plan(format!(
            "Join {side} input has multiple {ACTIVATOR_COL_NAME} columns"
        )));
    }
    let Some(activator_col) = activator_cols.into_iter().next() else {
        return Err(DataFusionError::Plan(format!(
            "Join {side} input is missing {ACTIVATOR_COL_NAME}"
        )));
    };
    let df = df.filter(Expr::Column(activator_col).eq(lit(true)))?;
    let mut projection_exprs = Vec::new();
    let mut row_id_col: Option<Column> = None;
    for (qualifier, field) in df.schema().iter() {
        if field.name() == ACTIVATOR_COL_NAME {
            continue;
        }
        if field.name() == ROW_ID_COL_NAME {
            if row_id_col.is_some() {
                return Err(DataFusionError::Plan(format!(
                    "Join {side} input has multiple {ROW_ID_COL_NAME} columns"
                )));
            }
            projection_exprs.push(
                Expr::Column(Column::new(qualifier.cloned(), ROW_ID_COL_NAME)).alias(row_id_alias),
            );
            row_id_col = Some(Column::from_name(row_id_alias));
            continue;
        }
        projection_exprs.push(Expr::Column(Column::new(qualifier.cloned(), field.name())));
    }
    let Some(row_id_col) = row_id_col else {
        return Err(DataFusionError::Plan(format!(
            "Join {side} input is missing {ROW_ID_COL_NAME}"
        )));
    };
    let df = df.select(projection_exprs)?;
    Ok((df, row_id_col))
}

fn payload_template_columns(df: &DataFrame, row_id_name: &str) -> DataFusionResult<Vec<Column>> {
    Ok(df
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            if field.name() == ACTIVATOR_COL_NAME
                || field.name() == row_id_name
            {
                None
            } else {
                Some(Column::new(qualifier.cloned(), field.name()))
            }
        })
        .collect::<Vec<_>>())
}

fn resolve_payload_exprs(
    df: &DataFrame,
    templates: &[Column],
) -> DataFusionResult<Vec<Expr>> {
    templates
        .iter()
        .map(|template| resolve_column_like(df, template).map(Expr::Column))
        .collect()
}

fn indexed_aliases(prefix: &str, len: usize) -> Vec<String> {
    (0..len).map(|idx| format!("{prefix}_{idx}")).collect()
}

fn with_helper_col(mut exprs: Vec<Expr>, helper_col: &str) -> Vec<Expr> {
    exprs.push(col(ACTIVATOR_COL_NAME));
    exprs.push(col(helper_col));
    exprs
}

fn with_activator_only(mut exprs: Vec<Expr>) -> Vec<Expr> {
    exprs.push(col(ACTIVATOR_COL_NAME));
    exprs
}

fn materialize_dataframe(df: DataFrame) -> DataFusionResult<DataFrame> {
    let df = crate::irs::nodes::hints::sort_by_row_id_if_present(df)?;
    let batches = collect_blocking(df)?;
    let ctx = SessionContext::new();
    if batches.is_empty() {
        return ctx.read_batch(RecordBatch::new_empty(
            Arc::new(datafusion::arrow::datatypes::Schema::empty()),
        ));
    }
    let schema_ref = batches[0].schema();
    let batch_refs = batches.iter().collect::<Vec<_>>();
    let combined = concat_batches(&schema_ref, batch_refs)?;
    ctx.read_batch(combined)
}

fn collect_blocking(df: DataFrame) -> DataFusionResult<Vec<RecordBatch>> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => match handle.runtime_flavor() {
            RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(df.collect()))
            }
            RuntimeFlavor::CurrentThread => {
                let df_clone = df.clone();
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| DataFusionError::Execution(e.to_string()))?;
                    rt.block_on(df_clone.collect())
                })
                .join()
                .map_err(|_| {
                    DataFusionError::Execution("dataframe collection thread panicked".to_string())
                })?
            }
            _ => tokio::task::block_in_place(|| handle.block_on(df.collect())),
        },
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| DataFusionError::Execution(e.to_string()))?;
            rt.block_on(df.collect())
        }
    }
}

fn expr_has_system_column(expr: &Expr) -> bool {
    expr.column_refs()
        .iter()
        .any(|col| col.name == ACTIVATOR_COL_NAME || col.name == ROW_ID_COL_NAME)
}

fn should_retry_source_mapping_without_aliased_row_ids(err: &DataFusionError) -> bool {
    let msg = format!("{err:?}");
    msg.contains(ROW_ID_COL_NAME) && msg.contains("AmbiguousReference")
}

fn resolve_column_like(df: &DataFrame, template: &Column) -> DataFusionResult<Column> {
    let mut exact = df
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            if field.name().as_str() == template.name.as_str()
                && qualifier == template.relation.as_ref()
            {
                Some(Column::new(qualifier.cloned(), field.name()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if exact.len() == 1 {
        return Ok(exact.remove(0));
    }

    let mut matches = df
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            if field.name().as_str() == template.name.as_str() {
                Some(Column::new(qualifier.cloned(), field.name()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(DataFusionError::Plan(format!(
            "Join source mapping column {} not found after join",
            template.name
        ))),
        _ => Err(DataFusionError::Plan(format!(
            "Join source mapping column {} is ambiguous after join",
            template.name
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::build_source_dfs;
    use super::{SRC_LEFT_COL_NAME, SRC_RIGHT_COL_NAME};
    use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
    use datafusion::arrow::{
        array::{ArrayRef, BooleanArray, Int32Array, Int64Array},
        compute::concat_batches,
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    };
    use datafusion::functions_window::expr_fn::row_number;
    use datafusion::prelude::SessionContext;
    use datafusion_common::{Column, TableReference};
    use datafusion_expr::{col, lit, Expr, ExprFunctionExt, JoinType, LogicalPlan};
    use std::sync::Arc;

    fn build_df(
        ctx: &SessionContext,
        rows: &[(i64, i32, i32, bool)],
        alias: &str,
    ) -> datafusion_common::Result<datafusion::prelude::DataFrame> {
        let row_ids: Vec<i64> = rows.iter().map(|(row_id, _, _, _)| *row_id).collect();
        let keys: Vec<i32> = rows.iter().map(|(_, key, _, _)| *key).collect();
        let vals: Vec<i32> = rows.iter().map(|(_, _, val, _)| *val).collect();
        let activators: Vec<bool> = rows.iter().map(|(_, _, _, active)| *active).collect();
        let schema = Arc::new(Schema::new(vec![
            Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
            Field::new("key", DataType::Int32, false),
            Field::new("val", DataType::Int32, false),
            Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
        ]));
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![
                Arc::new(Int64Array::from(row_ids)) as ArrayRef,
                Arc::new(Int32Array::from(keys)) as ArrayRef,
                Arc::new(Int32Array::from(vals)) as ArrayRef,
                Arc::new(BooleanArray::from(activators)) as ArrayRef,
            ],
        )?;
        ctx.read_batch(batch)?.alias(alias)
    }

    async fn collect_source_rows(
        df: datafusion::prelude::DataFrame,
        src_col_name: &str,
    ) -> Vec<(i64, bool, i64)> {
        let batches = df.collect().await.expect("collect should succeed");
        if batches.is_empty() {
            return Vec::new();
        }
        let combined =
            concat_batches(&batches[0].schema(), &batches).expect("concat should succeed");
        let src = combined
            .column_by_name(src_col_name)
            .expect("expected src column")
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("expected i64 column");
        let activator = combined
            .column_by_name(ACTIVATOR_COL_NAME)
            .expect("expected activator column")
            .as_any()
            .downcast_ref::<BooleanArray>()
            .expect("expected bool column");
        let row_id = combined
            .column_by_name(ROW_ID_COL_NAME)
            .expect("expected row id column")
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("expected i64 row id column");
        (0..src.len())
            .map(|idx| (src.value(idx), activator.value(idx), row_id.value(idx)))
            .collect()
    }

    fn join_plan_from_df(df: &datafusion::prelude::DataFrame) -> datafusion_expr::Join {
        match df.logical_plan() {
            LogicalPlan::Join(join) => join.clone(),
            _ => panic!("expected a join logical plan"),
        }
    }

    fn build_output_df(
        left_df: datafusion::prelude::DataFrame,
        right_df: datafusion::prelude::DataFrame,
        join_type: JoinType,
        left_key: Expr,
        right_key: Expr,
    ) -> datafusion::prelude::DataFrame {
        let prepare_input = |df: datafusion::prelude::DataFrame, row_id_label: &str| {
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
                .expect("output input projection should succeed")
        };

        let left_df = prepare_input(left_df, "__left_row_id__");
        let right_df = prepare_input(right_df, "__right_row_id__");
        let joined = left_df
            .join_on(right_df, join_type, vec![left_key.eq(right_key)])
            .expect("output join should succeed");

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
            data_exprs.push(Expr::Column(Column::new(qualifier.cloned(), field.name())));
        }

        let row_id_sort_exprs = vec![
            left_row_id
                .expect("left row_id should exist")
                .sort(true, true),
            right_row_id
                .expect("right row_id should exist")
                .sort(true, true),
        ];
        let joined = joined
            .sort(row_id_sort_exprs.clone())
            .expect("output sort should succeed");

        let row_number_expr = row_number()
            .partition_by(Vec::new())
            .order_by(row_id_sort_exprs)
            .build()
            .expect("row_number should build")
            .alias("__row_number__");
        let mut projection_exprs = data_exprs;
        projection_exprs.push(lit(true).alias(ACTIVATOR_COL_NAME));
        projection_exprs.push(row_number_expr);
        let with_row_number = joined
            .select(projection_exprs)
            .expect("output row_number projection should succeed");

        let mut final_exprs = Vec::new();
        for (qualifier, field) in with_row_number.schema().iter() {
            if field.name() == "__row_number__" {
                continue;
            }
            final_exprs.push(Expr::Column(Column::new(qualifier.cloned(), field.name())));
        }
        final_exprs.push((col("__row_number__") - lit(1_i64)).alias(ROW_ID_COL_NAME));
        with_row_number
            .select(final_exprs)
            .expect("output row_id projection should succeed")
    }

    async fn assert_source_mapping(
        left_rows: &[(i64, i32, i32, bool)],
        right_rows: &[(i64, i32, i32, bool)],
        expected_left: &[(i64, bool, i64)],
        expected_right: &[(i64, bool, i64)],
    ) {
        let ctx = SessionContext::new();
        let left_df = build_df(&ctx, left_rows, "l").unwrap();
        let right_df = build_df(&ctx, right_rows, "r").unwrap();

        let left_key = Expr::Column(Column::new(Some(TableReference::bare("l")), "key"));
        let right_key = Expr::Column(Column::new(Some(TableReference::bare("r")), "key"));
        let join_df = left_df
            .clone()
            .join_on(
                right_df.clone(),
                JoinType::Inner,
                vec![left_key.clone().eq(right_key.clone())],
            )
            .expect("join should succeed");

        let join = join_plan_from_df(&join_df);
        let output_df = build_output_df(
            left_df.clone(),
            right_df.clone(),
            JoinType::Inner,
            left_key,
            right_key,
        );
        let (left_src, right_src) =
            build_source_dfs(left_df, right_df, output_df, &join).expect("source dfs should build");
        let left_vals = collect_source_rows(left_src, SRC_LEFT_COL_NAME).await;
        let right_vals = collect_source_rows(right_src, SRC_RIGHT_COL_NAME).await;

        assert_eq!(left_vals, expected_left);
        assert_eq!(right_vals, expected_right);
    }

    #[tokio::test]
    async fn source_mapping_basic_inner_join() {
        // Scenario: one-to-one join.
        // Inputs:
        // - left rows:  (row_id=10, key=1, val=100)
        // - right rows: (row_id=20, key=1, val=200)
        // Join on key == key, so the single output row maps to:
        // - left src row_id: 10
        // - right src row_id: 20
        assert_source_mapping(
            &[(10, 1, 100, true)],
            &[(20, 1, 200, true)],
            &[(10, true, 0)],
            &[(20, true, 0)],
        )
        .await;
    }

    #[tokio::test]
    async fn source_mapping_duplicate_keys_cartesian() {
        // Scenario: duplicate keys on both sides.
        // Inputs:
        // - left rows:  (row_id=1, key=1, val=10), (row_id=3, key=1, val=11)
        // - right rows: (row_id=2, key=1, val=20), (row_id=4, key=1, val=21)
        // Join on key == key, so the output is a 2x2 Cartesian product.
        // Output ordering is by (left_row_id, right_row_id), so the src lists are:
        // - left src row_id:  1, 1, 3, 3
        // - right src row_id: 2, 4, 2, 4
        assert_source_mapping(
            &[(1, 1, 10, true), (3, 1, 11, true)],
            &[(2, 1, 20, true), (4, 1, 21, true)],
            &[(1, true, 0), (1, true, 1), (3, true, 2), (3, true, 3)],
            &[(2, true, 0), (4, true, 1), (2, true, 2), (4, true, 3)],
        )
        .await;
    }

    #[tokio::test]
    async fn source_mapping_no_matches_is_empty() {
        // Scenario: no matching keys.
        // Inputs:
        // - left rows:  (row_id=1, key=1, val=10)
        // - right rows: (row_id=2, key=2, val=20)
        // Join on key == key yields no rows, so both src outputs are empty.
        assert_source_mapping(&[(1, 1, 10, true)], &[(2, 2, 20, true)], &[], &[]).await;
    }

    #[tokio::test]
    async fn source_mapping_ignores_inactive_rows_and_preserves_sorted_row_ids() {
        // Scenario: one inactive row on each side should be ignored before source
        // reconstruction, and the final source tables should be sorted by their fresh
        // output row ids.
        assert_source_mapping(
            &[
                (8, 1, 100, false),
                (3, 1, 101, true),
                (7, 2, 102, true),
            ],
            &[
                (9, 1, 200, true),
                (4, 1, 201, false),
                (6, 2, 202, true),
            ],
            &[(3, true, 0), (7, true, 1)],
            &[(9, true, 0), (6, true, 1)],
        )
        .await;
    }
}

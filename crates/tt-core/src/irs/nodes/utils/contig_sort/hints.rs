use crate::irs::nodes::utils::contig_sort::{
    ROTATED_INPUT_LABEL, TIE_INDICATOR_LABEL, key_positions,
};
use crate::session::session_context;
use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME, is_system_column};
use datafusion::arrow::{
    array::{Array, ArrayRef, BooleanArray},
    compute::{
        LexicographicalComparator, SortColumn, SortOptions, and, concat, concat_batches,
        kernels::cmp::not_distinct,
    },
    datatypes::{DataType, Field, Schema},
    record_batch::RecordBatch,
};
use datafusion::logical_expr::col;
use datafusion::prelude::DataFrame;
use datafusion_common::{DataFusionError, Result as DataFusionResult};
use datafusion_expr::SortExpr;
use rayon::prelude::*;

use indexmap::IndexMap;

/// Inserts the rotated table and the tie indicators of `padded`, the sorted
/// and padded input, a table of `batches`.
pub(crate) fn populate_rotated_and_ties(
    gadget_payload: &mut IndexMap<String, crate::irs::nodes::hints::HintDF>,
    padded: &DataFrame,
    batches: &[RecordBatch],
    sort_specs: &[(String, bool, bool)],
) -> DataFusionResult<()> {
    let ordered = sort_padded(padded, batches, sort_specs)?;

    let rotated_df = session_context().read_batch(rotate(&ordered)?)?;
    let should_materialize = rotated_df
        .schema()
        .fields()
        .iter()
        .map(|field| (field.clone(), field.name() != ROW_ID_COL_NAME))
        .collect();
    gadget_payload.insert(
        ROTATED_INPUT_LABEL.to_string(),
        crate::irs::nodes::hints::HintDF::new(rotated_df, should_materialize),
    );

    if let Some(ties) = tie_indicators(&ordered, sort_specs)? {
        let tie_df = session_context().read_batch(ties)?;
        let should_materialize = tie_df
            .schema()
            .fields()
            .iter()
            .map(|field| (field.clone(), true))
            .collect();
        gadget_payload.insert(
            TIE_INDICATOR_LABEL.to_string(),
            crate::irs::nodes::hints::HintDF::new(tie_df, should_materialize),
        );
    }
    Ok(())
}

pub(crate) fn sort_input_for_contig_sort(
    input_hint: &crate::irs::nodes::hints::HintDF,
    sort_specs: &[(String, bool, bool)],
) -> DataFusionResult<DataFrame> {
    let df = input_hint.data_frame();
    let keys = sort_keys(df.schema().as_ref(), sort_specs)?;
    df.clone().sort(sort_exprs(&keys))
}

/// The rows of `padded` in one batch, in the order and schema DataFusion's
/// sort by the sort keys gives them; the rotation and the ties follow it.
/// That sort keeps rows already in order in place, unless a run of rows equal
/// on every key crosses a batch boundary (its merge interleaves them), and
/// returns a lone batch in its own schema and several merged into the
/// table's. Padding a Boolean key with `false` can break the order.
fn sort_padded(
    padded: &DataFrame,
    batches: &[RecordBatch],
    sort_specs: &[(String, bool, bool)],
) -> DataFusionResult<RecordBatch> {
    let table_schema = std::sync::Arc::clone(padded.schema().inner());
    let keys = sort_keys(&table_schema, sort_specs)?;
    if keys.is_empty() {
        return Err(DataFusionError::Plan(format!(
            "rotate requires {} column for deterministic ordering",
            ROW_ID_COL_NAME
        )));
    }
    let rows = match batches {
        [batch] => batch.clone(),
        _ => concat_batches(&table_schema, batches)?,
    };
    let columns = keys
        .iter()
        .map(|(name, options)| {
            Ok(SortColumn {
                values: rows.column(rows.schema().index_of(name)?).clone(),
                options: Some(*options),
            })
        })
        .collect::<DataFusionResult<Vec<_>>>()?;
    let comparator = LexicographicalComparator::try_new(&columns)?;
    let in_order = (1..rows.num_rows())
        .into_par_iter()
        .all(|row| comparator.compare(row - 1, row).is_le());
    let tie_across_batches = batches
        .iter()
        .scan(0, |end, batch| {
            *end += batch.num_rows();
            Some(*end)
        })
        .filter(|&end| end > 0 && end < rows.num_rows())
        .any(|end| comparator.compare(end - 1, end).is_eq());
    if in_order && !tie_across_batches {
        return Ok(rows);
    }
    let sorted = crate::session::block_on(padded.clone().sort(sort_exprs(&keys))?.collect())?;
    concat_batches(&sorted[0].schema(), &sorted).map_err(Into::into)
}

/// The rotated table has no row ids and no activator: the sort check gives it
/// the public mask `C_{µ,s-1}`.
fn is_rotation_excluded(name: &str) -> bool {
    name == ROW_ID_COL_NAME || name == ACTIVATOR_COL_NAME
}

/// `d'[j] = d[j + 1]`. Only rows `j < s - 1` are read, so the last row (here
/// `d[0]`) is arbitrary. `ordered` has a power-of-two number of rows, at
/// least two.
fn rotate(ordered: &RecordBatch) -> DataFusionResult<RecordBatch> {
    let row_count = ordered.num_rows();
    let schema = ordered.schema();
    let kept: Vec<(Field, &ArrayRef)> = schema
        .fields()
        .iter()
        .zip(ordered.columns())
        .filter(|(field, _)| !is_rotation_excluded(field.name()))
        .map(|(field, column)| (field.as_ref().clone(), column))
        .collect();
    let (fields, columns): (Vec<Field>, Vec<ArrayRef>) = kept
        .into_par_iter()
        .map(|(field, column)| {
            let tail = column.slice(1, row_count - 1);
            let head = column.slice(0, 1);
            Ok((field, concat(&[tail.as_ref(), head.as_ref()])?))
        })
        .collect::<DataFusionResult<Vec<_>>>()?
        .into_iter()
        .unzip();
    let out_schema =
        std::sync::Arc::new(Schema::new_with_metadata(fields, schema.metadata().clone()));
    RecordBatch::try_new(out_schema, columns).map_err(Into::into)
}

/// The committed tie indicators `tie_1..tie_{k-1}`: `tie_j` is true on row i
/// iff rows i and i+1 match on the first `j` keys, NULL matching NULL. `None`
/// for fewer than two keys, where only the public `tie_0` remains.
fn tie_indicators(
    ordered: &RecordBatch,
    sort_specs: &[(String, bool, bool)],
) -> DataFusionResult<Option<RecordBatch>> {
    let schema = ordered.schema();
    let key_cols = key_names(schema.as_ref(), sort_specs)?;
    if key_cols.len() < 2 {
        return Ok(None);
    }
    let row_count = ordered.num_rows();
    let matches = key_cols[..key_cols.len() - 1]
        .par_iter()
        .map(|name| {
            let column = ordered.column(schema.index_of(name)?);
            Ok(not_distinct(
                &column.slice(0, row_count - 1),
                &column.slice(1, row_count - 1),
            )?)
        })
        .collect::<DataFusionResult<Vec<BooleanArray>>>()?;

    let last_row = BooleanArray::from(vec![false]);
    let mut out_fields = Vec::with_capacity(matches.len());
    let mut out_cols = Vec::with_capacity(matches.len());
    let mut prefix: Option<BooleanArray> = None;
    for (prefix_len, matched) in (1..).zip(matches) {
        let tied = match prefix {
            Some(prefix) => and(&prefix, &matched)?,
            None => matched,
        };
        out_fields.push(Field::new(
            format!("tie_{prefix_len}"),
            DataType::Boolean,
            false,
        ));
        out_cols.push(concat(&[&tied as &dyn Array, &last_row])?);
        prefix = Some(tied);
    }

    let out_schema = std::sync::Arc::new(Schema::new(out_fields));
    RecordBatch::try_new(out_schema, out_cols)
        .map(Some)
        .map_err(Into::into)
}

/// The data columns of `schema` holding the sort keys, in key order.
fn key_names(
    schema: &Schema,
    sort_specs: &[(String, bool, bool)],
) -> DataFusionResult<Vec<String>> {
    let data_cols: Vec<String> = schema
        .fields()
        .iter()
        .map(|field| field.name().to_string())
        .filter(|name| !is_system_column(name))
        .collect();
    let positions = key_positions(data_cols.iter().map(String::as_str), sort_specs)
        .map_err(DataFusionError::Plan)?;
    Ok(positions
        .into_iter()
        .map(|position| data_cols[position].clone())
        .collect())
}

/// Activator first (active rows first), then the keys, then `__row_id__`.
/// NULLS LAST throughout, as padding and rotation assume.
fn sort_keys(
    schema: &Schema,
    sort_specs: &[(String, bool, bool)],
) -> DataFusionResult<Vec<(String, SortOptions)>> {
    let mut keys = Vec::new();
    if schema
        .fields()
        .iter()
        .any(|field| field.name() == ACTIVATOR_COL_NAME)
    {
        keys.push((
            ACTIVATOR_COL_NAME.to_string(),
            SortOptions {
                descending: true,
                nulls_first: false,
            },
        ));
    }
    for (name, (_, asc, _)) in key_names(schema, sort_specs)?.into_iter().zip(sort_specs) {
        keys.push((
            name,
            SortOptions {
                descending: !asc,
                nulls_first: false,
            },
        ));
    }
    if schema
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME)
    {
        // Row-id is only a deterministic tiebreaker once the sort order is fixed.
        keys.push((
            ROW_ID_COL_NAME.to_string(),
            SortOptions {
                descending: false,
                nulls_first: true,
            },
        ));
    }
    Ok(keys)
}

fn sort_exprs(keys: &[(String, SortOptions)]) -> Vec<SortExpr> {
    keys.iter()
        .map(|(name, options)| col(name.as_str()).sort(!options.descending, options.nulls_first))
        .collect()
}

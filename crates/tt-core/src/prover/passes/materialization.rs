use crate::irs::nodes::IsNode;
use crate::irs::nodes::hints::{
    FkRefColumns, QUALIFIER_METADATA_KEY, apply_constraint_metadata, table_name_from_qualifier,
};
use crate::{
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
        payloads::{HintDFPayload, PayloadStructure},
    },
    prover::payloads::{MaterializedPayload, MaterializedTable},
};
use ark_piop::SnarkBackend;
use datafusion::catalog::TableProvider;
use datafusion::{
    arrow::{
        array::{ArrayRef, BooleanArray, Int64Array, new_null_array},
        compute::{concat, concat_batches},
        datatypes::{Field, FieldRef, Schema},
        record_batch::{RecordBatch, RecordBatchOptions},
    },
    datasource::MemTable,
};
use datafusion_common::{Column, DFSchema, DataFusionError, ScalarValue};
use datafusion_expr::Expr;
use indexmap::IndexMap;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use std::sync::Arc;

/// Executes each hint dataframe into an in-memory table.
pub struct MaterializationPass<B>(std::marker::PhantomData<B>);
impl<B> MaterializationPass<B> {
    pub fn new() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<B> Default for MaterializationPass<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B> LocalPass<B, HintDFPayload, MaterializedPayload> for MaterializationPass<B>
where
    B: SnarkBackend,
{
    fn order(&self) -> crate::irs::ir::PassOrder {
        crate::irs::ir::PassOrder::PostOrder
    }
    fn transform(
        &self,
        node: &Node<B>,
        _id: NodeId,
        payload: Option<&HintDFPayload>,
    ) -> Option<MaterializedPayload> {
        let Some(payload) = payload else {
            tracing::debug!(node = %node.name(),  "skipped (no payload)");
            return None;
        };
        match payload {
            PayloadStructure::PlanPayload(hint_df) => {
                let materialized = materialize_hint_df(hint_df);
                tracing::debug!( node = %node.name(), typ= "plan", num_cols= materialized.as_ref().map_or(0, |m| m.mem_table().schema().fields().len()), num_rows= materialized.as_ref().map_or(0, |m| m.row_count()), "materialized");
                materialized.map(PayloadStructure::PlanPayload)
            }
            PayloadStructure::GadgetPayload(map) => {
                #[cfg(feature = "parallel")]
                let out: IndexMap<_, _> = map
                    .par_iter()
                    .filter_map(|(k, hint_df)| {
                        materialize_hint_df(hint_df).map(|mat| (k.clone(), mat))
                    })
                    .collect();

                #[cfg(not(feature = "parallel"))]
                let out: IndexMap<_, _> = map
                    .iter()
                    .filter_map(|(k, hint_df)| {
                        materialize_hint_df(hint_df).map(|mat| (k.clone(), mat))
                    })
                    .collect();

                out.iter()
                    .for_each(|(k, v)| tracing::debug!( node = %node.name(),typ= "gadget",  key=%k, num_cols = v.mem_table().schema().fields().len(), num_rows= v.row_count(), "materialized"));

                Some(PayloadStructure::GadgetPayload(out))
            }
        }
    }

    fn name(&self) -> &'static str {
        "Prover Materialization"
    }
}

fn materialize_hint_df(hint_df: &crate::irs::nodes::hints::HintDF) -> Option<MaterializedTable> {
    let df = hint_df.data_frame().clone();
    let df_schema = df.schema();
    // Qualifiers are kept: a bare name is `FieldNotFound` in a schema of
    // table-qualified columns.
    let projection: Vec<Expr> = hint_df
        .field_materialization_iter()
        .filter(|&(_field, should_mat)| *should_mat)
        .map(|(field, _should_mat)| projection_expr_for_field(df_schema, field))
        .collect();

    // The virtualization pass rebuilds a virtual-only payload; executing it
    // here would be wasted work.
    if projection.is_empty() {
        return None;
    }

    // Sort before projecting, while `__row_id__` is still in the schema.
    // Later nodes (e.g. the partial-join merge) take row i of the
    // materialized table to be row i of the FK input's `TrackedTable`, which
    // holds only in `__row_id__` order.
    let df = crate::irs::nodes::hints::sort_by_row_id_if_present(df)
        .expect("materialization row-id sort should succeed");
    let df = df
        .select(projection)
        .expect("materialization projection should succeed");

    let batches = crate::session::block_on(df.clone().collect())
        .expect("dataframe collection should succeed");

    let df_schema_ref = df.schema();
    let arrow_schema = arrow_schema_with_qualifiers(df_schema_ref);
    let (batches, row_count) =
        pad_batches_to_power_of_two(&arrow_schema, batches).expect("padding should succeed");

    let mem_batches = batches.clone();
    let mem_table =
        MemTable::try_new(Arc::new(arrow_schema), vec![mem_batches]).expect("memtable creation");
    // Store batches so arithmetization can bypass DataFusion schema name checks.
    Some(MaterializedTable::new_with_batches(
        mem_table, row_count, batches,
    ))
}

pub fn append_activator_and_pad_batches(
    base_schema: &Schema,
    batches: Vec<RecordBatch>,
) -> datafusion_common::Result<(Schema, Vec<RecordBatch>)> {
    let row_count: usize = batches.iter().map(|batch| batch.num_rows()).sum();
    let target_num_rows = row_count.max(1).next_power_of_two();
    let has_activator = base_schema
        .fields()
        .iter()
        .any(|field| field.name() == arithmetic::ACTIVATOR_COL_NAME);
    let padded_batches =
        pad_batches_to_num_rows_with_inactive_padding(base_schema, batches, Some(target_num_rows))?;
    if has_activator {
        return Ok((base_schema.clone(), padded_batches));
    }
    let batch_refs: Vec<&RecordBatch> = padded_batches.iter().collect();
    let combined = concat_batches(&Arc::new(base_schema.clone()), batch_refs)?;

    let mut output_fields = base_schema.fields().to_vec();
    output_fields.push(Arc::new(Field::new(
        arithmetic::ACTIVATOR_COL_NAME,
        datafusion::arrow::datatypes::DataType::Boolean,
        false,
    )));
    let output_schema = Schema::new(output_fields);

    let activator_values = std::iter::repeat_n(true, row_count)
        .chain(std::iter::repeat_n(false, target_num_rows - row_count))
        .collect::<Vec<_>>();
    let mut arrays = combined.columns().to_vec();
    arrays.push(Arc::new(BooleanArray::from(activator_values)) as ArrayRef);
    let combined_batch = RecordBatch::try_new(Arc::new(output_schema.clone()), arrays)?;
    Ok((output_schema, vec![combined_batch]))
}

pub fn pad_batches_to_num_rows_with_inactive_padding(
    schema: &Schema,
    batches: Vec<RecordBatch>,
    target_num_rows: Option<usize>,
) -> datafusion_common::Result<Vec<RecordBatch>> {
    let row_count: usize = batches.iter().map(|batch| batch.num_rows()).sum();
    let Some(target_num_rows) = target_num_rows else {
        return Ok(batches);
    };
    if row_count > target_num_rows {
        return Err(DataFusionError::Internal(format!(
            "cannot pad output memtable from {} rows down to {} rows",
            row_count, target_num_rows
        )));
    }
    if row_count == target_num_rows {
        return Ok(batches);
    }

    let schema_ref = Arc::new(schema.clone());
    let combined = if row_count == 0 || schema.fields().is_empty() {
        None
    } else {
        let batch_refs: Vec<&RecordBatch> = batches.iter().collect();
        Some(concat_batches(&schema_ref, batch_refs)?)
    };

    let pad = target_num_rows - row_count;
    let mut output_arrays = Vec::with_capacity(schema.fields().len());
    for (idx, field) in schema.fields().iter().enumerate() {
        let base = combined
            .as_ref()
            .map(|batch| batch.column(idx).clone())
            .unwrap_or_else(|| {
                inactive_padding_scalar(field.data_type())
                    .expect("padding scalar for schema field")
                    .to_array_of_size(0)
                    .expect("empty array for schema field")
            });
        let pad_arr = if field.name() == arithmetic::ACTIVATOR_COL_NAME {
            Arc::new(BooleanArray::from(vec![false; pad])) as ArrayRef
        } else {
            inactive_padding_scalar(field.data_type())?.to_array_of_size(pad)?
        };
        output_arrays.push(concat(&[base.as_ref(), pad_arr.as_ref()])?);
    }

    let padded_batch = RecordBatch::try_new(schema_ref, output_arrays)?;
    Ok(vec![padded_batch])
}

pub fn inactive_padding_scalar(
    data_type: &datafusion::arrow::datatypes::DataType,
) -> datafusion_common::Result<ScalarValue> {
    match ScalarValue::new_zero(data_type) {
        Ok(value) => Ok(value),
        Err(_) => match data_type {
            datafusion::arrow::datatypes::DataType::Utf8View => {
                Ok(ScalarValue::Utf8View(Some(String::new())))
            }
            datafusion::arrow::datatypes::DataType::BinaryView => {
                Ok(ScalarValue::BinaryView(Some(Vec::new())))
            }
            datafusion::arrow::datatypes::DataType::FixedSizeBinary(size) => Ok(
                ScalarValue::FixedSizeBinary(*size, Some(vec![0; *size as usize])),
            ),
            _ => Err(DataFusionError::NotImplemented(format!(
                "unsupported inactive padding type: {data_type:?}"
            ))),
        },
    }
}

fn arrow_schema_with_qualifiers(df_schema: &DFSchema) -> Schema {
    let arrow_schema: Schema = <DFSchema as AsRef<Schema>>::as_ref(df_schema).clone();
    let fields: Vec<Field> = df_schema
        .iter()
        .map(|(qualifier, field)| {
            let mut updated = field.as_ref().clone();
            if updated.name() == arithmetic::ACTIVATOR_COL_NAME
                || updated.name() == arithmetic::ROW_ID_COL_NAME
            {
                return updated;
            }
            if let Some(qualifier) = qualifier {
                // The qualifier lets later lookups tell same-name columns apart.
                let mut metadata = updated.metadata().clone();
                let qualifier_str = qualifier.to_string();
                metadata.insert(QUALIFIER_METADATA_KEY.to_string(), qualifier_str.clone());
                apply_constraint_metadata(
                    &mut metadata,
                    &table_name_from_qualifier(&qualifier_str),
                    updated.name(),
                    FkRefColumns::Paired,
                );
                updated = updated.with_metadata(metadata);
            }
            updated
        })
        .collect();
    Schema::new_with_metadata(fields, arrow_schema.metadata().clone())
}

/// Pads collected batches to the next power-of-two row count with the
/// inactive padding of materialization: `false` activator, `false` booleans,
/// null strings, repeat-last for other columns. Plan-time witness scans
/// (e.g. the LIKE gadget re-scanning a compacted input) must pad exactly
/// like this, or their witness diverges from the commitments.
pub fn pad_batches_to_power_of_two(
    schema: &Schema,
    batches: Vec<RecordBatch>,
) -> datafusion_common::Result<(Vec<RecordBatch>, usize)> {
    let row_count: usize = batches.iter().map(|b| b.num_rows()).sum();
    if row_count == 0 {
        let target = 2;
        let schema_ref = Arc::new(schema.clone());
        if schema_ref.fields().is_empty() {
            let options = RecordBatchOptions::new().with_row_count(Some(target));
            let out_batch = RecordBatch::try_new_with_options(schema_ref, vec![], &options)?;
            return Ok((vec![out_batch], target));
        }

        let mut output_arrays = Vec::with_capacity(schema_ref.fields().len());
        for field in schema_ref.fields().iter() {
            let padded = if field.name() == arithmetic::ACTIVATOR_COL_NAME {
                Arc::new(BooleanArray::from(vec![false; target])) as ArrayRef
            } else if field.name() == arithmetic::ROW_ID_COL_NAME {
                let vals: Vec<i64> = (0..target as i64).collect();
                Arc::new(Int64Array::from(vals)) as ArrayRef
            } else {
                let null = ScalarValue::try_new_null(field.data_type())?;
                null.to_array_of_size(target)?
            };
            output_arrays.push(padded);
        }

        let out_batch = RecordBatch::try_new(schema_ref, output_arrays)?;
        return Ok((vec![out_batch], target));
    }
    let target = row_count.next_power_of_two();
    let pad = target - row_count;
    if pad == 0 {
        let batches = rewrap_batches_with_schema(schema, batches)?;
        return Ok((batches, row_count));
    }

    let schema_ref = Arc::new(schema.clone());
    if schema_ref.fields().is_empty() {
        // Arrow requires an explicit row count when constructing a zero-column batch.
        let options = RecordBatchOptions::new().with_row_count(Some(target));
        let out_batch = RecordBatch::try_new_with_options(schema_ref, vec![], &options)?;
        return Ok((vec![out_batch], target));
    }
    let combined = if batches.is_empty() {
        None
    } else {
        let batch_refs: Vec<&RecordBatch> = batches.iter().collect();
        Some(concat_batches(&schema_ref, batch_refs)?)
    };

    let mut output_arrays = Vec::with_capacity(schema_ref.fields().len());
    for (idx, field) in schema_ref.fields().iter().enumerate() {
        let padded = if field.name() == arithmetic::ACTIVATOR_COL_NAME {
            let base = combined
                .as_ref()
                .map(|batch| batch.column(idx).clone())
                .unwrap_or_else(|| Arc::new(BooleanArray::from(Vec::<bool>::new())) as ArrayRef);
            let pad_arr: ArrayRef = Arc::new(BooleanArray::from(vec![false; pad]));
            concat(&[base.as_ref(), pad_arr.as_ref()])?
        } else if crate::irs::lineage::is_string_type(field.data_type()) {
            // A string column's padding must be null, not a repeat of the
            // last row. The encoder marks every character of a non-null row
            // active, so a repeated string would put active characters under
            // an inactive row and break the compaction DPUC's
            // activator/length relation (`Σ_{orig-ind = i} char-act =
            // a[i]·l[i]`, which is 0 for a padding row). A null encodes to
            // length 0 with no characters.
            let base = combined
                .as_ref()
                .map(|batch| batch.column(idx).clone())
                .unwrap_or_else(|| new_null_array(field.data_type(), 0));
            let null = ScalarValue::try_new_null(field.data_type())?;
            let pad_arr = null.to_array_of_size(pad)?;
            concat(&[base.as_ref(), pad_arr.as_ref()])?
        } else if field.data_type() == &datafusion::arrow::datatypes::DataType::Boolean {
            // False on padded rows, so that padding adds no accidental truth
            // constraint.
            let base = combined
                .as_ref()
                .map(|batch| batch.column(idx).clone())
                .unwrap_or_else(|| Arc::new(BooleanArray::from(Vec::<bool>::new())) as ArrayRef);
            let pad_arr: ArrayRef = Arc::new(BooleanArray::from(vec![false; pad]));
            concat(&[base.as_ref(), pad_arr.as_ref()])?
        } else if let Some(batch) = combined.as_ref() {
            let base = batch.column(idx).clone();
            // Repeat-last padding keeps constraint wiring stable for non-boolean columns.
            let last = ScalarValue::try_from_array(base.as_ref(), row_count - 1)?;
            let pad_arr = last.to_array_of_size(pad)?;
            concat(&[base.as_ref(), pad_arr.as_ref()])?
        } else {
            let null = ScalarValue::try_new_null(field.data_type())?;
            null.to_array_of_size(pad)?
        };
        output_arrays.push(padded);
    }

    let out_batch = RecordBatch::try_new(schema_ref, output_arrays)?;
    Ok((vec![out_batch], target))
}

fn rewrap_batches_with_schema(
    schema: &Schema,
    batches: Vec<RecordBatch>,
) -> datafusion_common::Result<Vec<RecordBatch>> {
    if batches.is_empty() {
        return Ok(batches);
    }
    let schema_ref = Arc::new(schema.clone());
    let has_fields = !schema_ref.fields().is_empty();
    batches
        .into_iter()
        .map(|batch| {
            if has_fields {
                let columns = (0..batch.num_columns())
                    .map(|idx| batch.column(idx).clone())
                    .collect::<Vec<_>>();
                RecordBatch::try_new(schema_ref.clone(), columns)
                    .map_err(|e| DataFusionError::Execution(e.to_string()))
            } else {
                let options = RecordBatchOptions::new().with_row_count(Some(batch.num_rows()));
                RecordBatch::try_new_with_options(schema_ref.clone(), vec![], &options)
                    .map_err(|e| DataFusionError::Execution(e.to_string()))
            }
        })
        .collect()
}

fn projection_expr_for_field(schema: &DFSchema, field: &FieldRef) -> Expr {
    let name = field.name();
    if let Some(qualifier_meta) = field.metadata().get(QUALIFIER_METADATA_KEY)
        && let Some((qualifier, _)) = schema.iter().find(|(q, f)| {
            f.name() == name
                && q.as_ref().map(|q| q.to_string()) == Some(qualifier_meta.to_string())
        })
    {
        return Expr::Column(Column::new(qualifier.cloned(), name));
    }
    if let Some((qualifier, _)) = schema.iter().find(|(_, f)| f.name() == name) {
        return Expr::Column(Column::new(qualifier.cloned(), name));
    }
    if let Some((relation, col_name)) = name.split_once('.')
        && let Some((qualifier, _)) = schema.iter().find(|(q, f)| {
            f.name() == col_name && q.map(|q| q.to_string()) == Some(relation.to_string())
        })
    {
        return Expr::Column(Column::new(qualifier.cloned(), col_name));
    }
    Expr::Column(Column::new_unqualified(name))
}

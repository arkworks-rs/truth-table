use crate::irs::nodes::IsNode;
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
        array::{ArrayRef, BooleanArray, Int64Array},
        compute::{concat, concat_batches},
        datatypes::{Field, FieldRef, Schema},
        record_batch::{RecordBatch, RecordBatchOptions},
    },
    datasource::MemTable,
    prelude::DataFrame,
};
use datafusion_common::{Column, DFSchema, DataFusionError, ScalarValue};
use datafusion_expr::Expr;
use indexmap::IndexMap;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock, RwLock},
};
use tokio::runtime::RuntimeFlavor;

const QUALIFIER_METADATA_KEY: &str = "tt.qualifier";
const CONSTRAINTS_FILE_NAME: &str = "constraints.json";
const PK_METADATA_KEY: &str = "tt.pk";
const FK_REF_TABLE_METADATA_KEY: &str = "tt.fk.ref_table";
const FK_REF_COLUMNS_METADATA_KEY: &str = "tt.fk.ref_columns";

static CONSTRAINTS_BY_TABLE: OnceLock<RwLock<HashMap<String, TableConstraint>>> = OnceLock::new();

#[derive(Debug, Deserialize)]
struct ConstraintManifest {
    tables: Vec<TableConstraintSpec>,
}

#[derive(Debug, Deserialize)]
struct TableConstraintSpec {
    table: String,
    #[serde(default)]
    primary_key: Vec<String>,
    #[serde(default)]
    foreign_keys: Vec<ForeignKeySpec>,
}

#[derive(Debug, Deserialize)]
struct ForeignKeySpec {
    columns: Vec<String>,
    ref_table: String,
    ref_columns: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct TableConstraint {
    primary_key_cols: HashSet<String>,
    foreign_key_by_col: HashMap<String, ForeignKeyColConstraint>,
}

#[derive(Clone, Debug)]
struct ForeignKeyColConstraint {
    ref_table: String,
    ref_columns: Vec<String>,
}

/// A materialization pass that materializes the prover's hint DataFrames
///
/// This pass converts an IR with Hint DataFrame payloads into an IR with materialized in-memory tables.
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

/// Loads constraint manifests from directories that contain input parquet files.
///
/// Each `<parquet_dir>/constraints.json` is parsed when present; missing files
/// are ignored. The merged map is used by materialization to stamp `tt.pk` and
/// `tt.fk.*` metadata onto output schema fields.
pub fn configure_constraint_metadata_from_parquet_paths(parquet_paths: &[PathBuf]) {
    crate::irs::nodes::hints::configure_constraint_metadata_from_parquet_paths(parquet_paths);
    let mut merged = HashMap::new();
    for parquet_path in parquet_paths {
        let Some(dir) = parquet_path.parent() else {
            continue;
        };
        merge_constraints_from_dir(dir, &mut merged);
    }
    let lock = CONSTRAINTS_BY_TABLE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Ok(mut guard) = lock.write() {
        *guard = merged;
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
    // Build projection of columns marked for materialization, preserving qualifiers
    // to avoid `FieldNotFound` errors when the schema uses table-qualified columns.
    let projection: Vec<Expr> = hint_df
        .field_materialization_iter()
        .filter(|&(_field, should_mat)| *should_mat)
        .map(|(field, _should_mat)| projection_expr_for_field(df_schema, field))
        .collect();

    // Virtual-only payloads are reconstructed later by the virtualization pass.
    // Materializing them here only adds expensive DataFusion execution.
    if projection.is_empty() {
        return None;
    }

    let df = df
        .select(projection)
        .expect("materialization projection should succeed");

    let batches = collect_blocking(df.clone()).expect("dataframe collection should succeed");

    let df_schema_ref = df.schema();
    let arrow_schema = arrow_schema_with_qualifiers(&df_schema_ref);
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
                // Preserve qualifiers so downstream lookups can disambiguate same-name columns.
                let mut metadata = updated.metadata().clone();
                let qualifier_str = qualifier.to_string();
                metadata.insert(QUALIFIER_METADATA_KEY.to_string(), qualifier_str.clone());
                apply_constraint_metadata(
                    &mut metadata,
                    &table_name_from_qualifier(&qualifier_str),
                    updated.name(),
                );
                updated = updated.with_metadata(metadata);
            }
            updated
        })
        .collect();
    Schema::new_with_metadata(fields, arrow_schema.metadata().clone())
}

fn merge_constraints_from_dir(dir: &Path, out: &mut HashMap<String, TableConstraint>) {
    let path = dir.join(CONSTRAINTS_FILE_NAME);
    let Ok(raw) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(manifest) = serde_json::from_str::<ConstraintManifest>(&raw) else {
        return;
    };

    for table in manifest.tables {
        let key = table.table.to_lowercase();
        let mut constraint = TableConstraint {
            primary_key_cols: table
                .primary_key
                .into_iter()
                .map(|c| c.to_lowercase())
                .collect(),
            foreign_key_by_col: HashMap::new(),
        };

        for fk in table.foreign_keys {
            if fk.columns.is_empty() {
                continue;
            }
            // Store FK metadata per source column, pairing source and target columns
            // positionally for composite keys.
            for (idx, src_col) in fk.columns.iter().enumerate() {
                let ref_col = fk
                    .ref_columns
                    .get(idx)
                    .cloned()
                    .or_else(|| fk.ref_columns.first().cloned())
                    .into_iter()
                    .collect::<Vec<_>>();
                constraint.foreign_key_by_col.insert(
                    src_col.to_lowercase(),
                    ForeignKeyColConstraint {
                        ref_table: fk.ref_table.clone(),
                        ref_columns: ref_col,
                    },
                );
            }
        }

        out.insert(key, constraint);
    }
}

fn table_name_from_qualifier(qualifier: &str) -> String {
    qualifier
        .rsplit('.')
        .next()
        .unwrap_or(qualifier)
        .trim_matches('"')
        .trim_matches('`')
        .to_lowercase()
}

fn apply_constraint_metadata(
    metadata: &mut HashMap<String, String>,
    table_name: &str,
    column_name: &str,
) {
    let Some(lock) = CONSTRAINTS_BY_TABLE.get() else {
        return;
    };
    let Ok(guard) = lock.read() else {
        return;
    };
    let Some(table) = guard.get(table_name) else {
        return;
    };
    let column_key = column_name.to_lowercase();

    if table.primary_key_cols.contains(&column_key) {
        metadata.insert(PK_METADATA_KEY.to_string(), "true".to_string());
    }
    if let Some(fk) = table.foreign_key_by_col.get(&column_key) {
        metadata.insert(FK_REF_TABLE_METADATA_KEY.to_string(), fk.ref_table.clone());
        if let Ok(serialized) = serde_json::to_string(&fk.ref_columns) {
            metadata.insert(FK_REF_COLUMNS_METADATA_KEY.to_string(), serialized);
        }
    }
}

fn collect_blocking(df: DataFrame) -> datafusion_common::Result<Vec<RecordBatch>> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => match handle.runtime_flavor() {
            RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(df.collect()))
            }
            RuntimeFlavor::CurrentThread => {
                // Spawn a dedicated thread with its own runtime to avoid blocking a single-thread runtime.
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

fn pad_batches_to_power_of_two(
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
            // Padded rows are always inactive.
            let base = combined
                .as_ref()
                .map(|batch| batch.column(idx).clone())
                .unwrap_or_else(|| Arc::new(BooleanArray::from(Vec::<bool>::new())) as ArrayRef);
            let pad_arr: ArrayRef = Arc::new(BooleanArray::from(vec![false; pad]));
            concat(&[base.as_ref(), pad_arr.as_ref()])?
        } else if field.data_type() == &datafusion::arrow::datatypes::DataType::Boolean {
            // Keep boolean payload columns false on padded rows to avoid introducing
            // accidental truth constraints.
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
    if let Some(qualifier_meta) = field.metadata().get(QUALIFIER_METADATA_KEY) {
        if let Some((qualifier, _)) = schema.iter().find(|(q, f)| {
            f.name() == name
                && q.as_ref().map(|q| q.to_string()) == Some(qualifier_meta.to_string())
        }) {
            return Expr::Column(Column::new(qualifier.cloned(), name));
        }
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

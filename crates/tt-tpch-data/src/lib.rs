//! TPC-H data generation and padding for truth-table benchmarks and tests.
//!
//! The prover works on tables with a power-of-two row count and the
//! `__row_id__` and `__activator__` system columns. This crate writes TPC-H
//! data (from the `tpchgen` crate) as Parquet in that shape, with a
//! `constraints.json` next to it that gives the proof planner the primary
//! and foreign keys.

use std::{
    fs::{File, create_dir_all},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

use arithmetic::ACTIVATOR_COL_NAME;
use arrow::{
    array::{
        Array, ArrayRef, BooleanBuilder, Date32Array, Date64Array, Decimal128Array, Float32Array,
        Float64Array, Int32Builder, Int64Builder, RecordBatch, TimestampMicrosecondArray,
        TimestampMillisecondArray, TimestampNanosecondArray, TimestampSecondArray, UInt64Builder,
        new_null_array,
    },
    datatypes::{
        DataType, Date64Type, Field, Schema, TimeUnit, TimestampMicrosecondType,
        TimestampMillisecondType, TimestampNanosecondType, TimestampSecondType,
    },
    temporal_conversions::{as_datetime, date32_to_datetime},
};
use chrono::{Datelike, Timelike};
use duckdb::Connection;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::arrow_writer::ArrowWriter;
use serde::Serialize;
use tpchgen::generators::*;
use tpchgen_arrow::*;

const ROW_ID_COL_NAME: &str = "__row_id__";
const CONSTRAINTS_FILE_NAME: &str = "constraints.json";
const FIXED_PONEGLYPH_SCALE: f64 = 0.01;
const NORMAL_DECIMAL_PRECISION: u8 = 18;
const NORMAL_DECIMAL_SCALE: i8 = 3;

fn workspace_artifacts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("tt-tpch-data crate should live inside truth-table/crates")
        .join("artifacts")
}

#[derive(Clone, Debug, Serialize)]
struct ConstraintManifest {
    format_version: u32,
    source: &'static str,
    tables: Vec<TableConstraintSpec>,
}

#[derive(Clone, Debug, Serialize)]
struct TableConstraintSpec {
    table: String,
    primary_key: Vec<String>,
    unique_keys: Vec<Vec<String>>,
    foreign_keys: Vec<ForeignKeySpec>,
}

#[derive(Clone, Debug, Serialize)]
struct ForeignKeySpec {
    columns: Vec<String>,
    ref_table: String,
    ref_columns: Vec<String>,
}

fn tpch_constraints_manifest() -> ConstraintManifest {
    let mut tables = vec![
        TableConstraintSpec {
            table: "region".to_string(),
            primary_key: vec!["r_regionkey".to_string()],
            unique_keys: vec![],
            foreign_keys: vec![],
        },
        TableConstraintSpec {
            table: "nation".to_string(),
            primary_key: vec!["n_nationkey".to_string()],
            unique_keys: vec![],
            foreign_keys: vec![ForeignKeySpec {
                columns: vec!["n_regionkey".to_string()],
                ref_table: "region".to_string(),
                ref_columns: vec!["r_regionkey".to_string()],
            }],
        },
        TableConstraintSpec {
            table: "part".to_string(),
            primary_key: vec!["p_partkey".to_string()],
            unique_keys: vec![],
            foreign_keys: vec![],
        },
        TableConstraintSpec {
            table: "supplier".to_string(),
            primary_key: vec!["s_suppkey".to_string()],
            unique_keys: vec![],
            foreign_keys: vec![ForeignKeySpec {
                columns: vec!["s_nationkey".to_string()],
                ref_table: "nation".to_string(),
                ref_columns: vec!["n_nationkey".to_string()],
            }],
        },
        TableConstraintSpec {
            table: "partsupp".to_string(),
            primary_key: vec!["ps_partkey".to_string(), "ps_suppkey".to_string()],
            unique_keys: vec![],
            foreign_keys: vec![
                ForeignKeySpec {
                    columns: vec!["ps_partkey".to_string()],
                    ref_table: "part".to_string(),
                    ref_columns: vec!["p_partkey".to_string()],
                },
                ForeignKeySpec {
                    columns: vec!["ps_suppkey".to_string()],
                    ref_table: "supplier".to_string(),
                    ref_columns: vec!["s_suppkey".to_string()],
                },
            ],
        },
        TableConstraintSpec {
            table: "customer".to_string(),
            primary_key: vec!["c_custkey".to_string()],
            unique_keys: vec![],
            foreign_keys: vec![ForeignKeySpec {
                columns: vec!["c_nationkey".to_string()],
                ref_table: "nation".to_string(),
                ref_columns: vec!["n_nationkey".to_string()],
            }],
        },
        TableConstraintSpec {
            table: "orders".to_string(),
            primary_key: vec!["o_orderkey".to_string()],
            unique_keys: vec![],
            foreign_keys: vec![ForeignKeySpec {
                columns: vec!["o_custkey".to_string()],
                ref_table: "customer".to_string(),
                ref_columns: vec!["c_custkey".to_string()],
            }],
        },
        TableConstraintSpec {
            table: "lineitem".to_string(),
            primary_key: vec!["l_orderkey".to_string(), "l_linenumber".to_string()],
            unique_keys: vec![],
            foreign_keys: vec![
                ForeignKeySpec {
                    columns: vec!["l_orderkey".to_string()],
                    ref_table: "orders".to_string(),
                    ref_columns: vec!["o_orderkey".to_string()],
                },
                ForeignKeySpec {
                    columns: vec!["l_partkey".to_string(), "l_suppkey".to_string()],
                    ref_table: "partsupp".to_string(),
                    ref_columns: vec!["ps_partkey".to_string(), "ps_suppkey".to_string()],
                },
            ],
        },
    ];
    let poneglyph_tables: Vec<TableConstraintSpec> = tables
        .iter()
        .cloned()
        .map(|mut table| {
            table.table = format!("{}_poneglyph", table.table);
            for fk in &mut table.foreign_keys {
                fk.ref_table = format!("{}_poneglyph", fk.ref_table);
            }
            table
        })
        .collect();
    tables.extend(poneglyph_tables);

    ConstraintManifest {
        format_version: 1,
        source: "tpch-constraints-hardcoded",
        tables,
    }
}

fn write_constraints_manifest<P: AsRef<Path>>(out_dir: P) {
    let out_dir = out_dir.as_ref();
    create_dir_all(out_dir).expect("create output dir for constraints");
    let out_path = out_dir.join(CONSTRAINTS_FILE_NAME);
    let payload = serde_json::to_string_pretty(&tpch_constraints_manifest())
        .expect("serialize tpch constraints manifest");
    let mut file = File::create(&out_path).expect("create constraints manifest file");
    file.write_all(payload.as_bytes())
        .expect("write constraints manifest");
    file.write_all(b"\n")
        .expect("finalize constraints manifest");
}

#[derive(Clone)]
enum Expansion {
    Original(usize),
    Date32 { index: usize },
    Date64 { index: usize },
    Timestamp { index: usize, unit: TimeUnit },
}

fn build_expansions(schema: &Schema) -> (Vec<Expansion>, Vec<Field>) {
    let mut expansions = Vec::new();
    let mut fields = Vec::new();
    for (idx, field) in schema.fields().iter().enumerate() {
        match field.data_type() {
            DataType::Date32 => {
                let name = field.name().to_string();
                expansions.push(Expansion::Original(idx));
                expansions.push(Expansion::Date32 { index: idx });
                fields.push((**field).clone().with_nullable(true));
                fields.push(Field::new(format!("{name}_year"), DataType::Int32, true));
                fields.push(Field::new(format!("{name}_month"), DataType::Int32, true));
                fields.push(Field::new(format!("{name}_day"), DataType::Int32, true));
            }
            DataType::Date64 => {
                let name = field.name().to_string();
                expansions.push(Expansion::Original(idx));
                expansions.push(Expansion::Date64 { index: idx });
                fields.push((**field).clone().with_nullable(true));
                fields.push(Field::new(format!("{name}_year"), DataType::Int32, true));
                fields.push(Field::new(format!("{name}_month"), DataType::Int32, true));
                fields.push(Field::new(format!("{name}_day"), DataType::Int32, true));
                fields.push(Field::new(format!("{name}_time"), DataType::Int32, true));
            }
            DataType::Timestamp(unit, _) => {
                let name = field.name().to_string();
                expansions.push(Expansion::Original(idx));
                expansions.push(Expansion::Timestamp {
                    index: idx,
                    unit: *unit,
                });
                fields.push((**field).clone().with_nullable(true));
                fields.push(Field::new(format!("{name}_year"), DataType::Int32, true));
                fields.push(Field::new(format!("{name}_month"), DataType::Int32, true));
                fields.push(Field::new(format!("{name}_day"), DataType::Int32, true));
                fields.push(Field::new(format!("{name}_time"), DataType::Int32, true));
            }
            _ => {
                expansions.push(Expansion::Original(idx));
                fields.push((**field).clone().with_nullable(true));
            }
        }
    }
    (expansions, fields)
}

fn expand_batch(
    batch: &RecordBatch,
    expansions: &[Expansion],
    out_schema: &Arc<Schema>,
) -> RecordBatch {
    let mut cols: Vec<ArrayRef> = Vec::new();
    for expansion in expansions {
        match expansion {
            Expansion::Original(idx) => cols.push(batch.column(*idx).clone()),
            Expansion::Date32 { index, .. } => {
                let array = batch
                    .column(*index)
                    .as_any()
                    .downcast_ref::<Date32Array>()
                    .expect("date32 downcast");
                let mut year = Int32Builder::new();
                let mut month = Int32Builder::new();
                let mut day = Int32Builder::new();
                for i in 0..array.len() {
                    if array.is_null(i) {
                        year.append_null();
                        month.append_null();
                        day.append_null();
                        continue;
                    }
                    let dt = date32_to_datetime(array.value(i)).expect("date32 conversion");
                    year.append_value(dt.year() as i32);
                    month.append_value(dt.month() as i32);
                    day.append_value(dt.day() as i32);
                }
                cols.push(Arc::new(year.finish()));
                cols.push(Arc::new(month.finish()));
                cols.push(Arc::new(day.finish()));
            }
            Expansion::Date64 { index, .. } => {
                let array = batch
                    .column(*index)
                    .as_any()
                    .downcast_ref::<Date64Array>()
                    .expect("date64 downcast");
                let mut year = Int32Builder::new();
                let mut month = Int32Builder::new();
                let mut day = Int32Builder::new();
                let mut time = Int32Builder::new();
                for i in 0..array.len() {
                    if array.is_null(i) {
                        year.append_null();
                        month.append_null();
                        day.append_null();
                        time.append_null();
                        continue;
                    }
                    let dt = as_datetime::<Date64Type>(array.value(i)).expect("date64 conversion");
                    year.append_value(dt.year() as i32);
                    month.append_value(dt.month() as i32);
                    day.append_value(dt.day() as i32);
                    time.append_value(dt.time().num_seconds_from_midnight() as i32);
                }
                cols.push(Arc::new(year.finish()));
                cols.push(Arc::new(month.finish()));
                cols.push(Arc::new(day.finish()));
                cols.push(Arc::new(time.finish()));
            }
            Expansion::Timestamp { index, unit, .. } => {
                let mut year = Int32Builder::new();
                let mut month = Int32Builder::new();
                let mut day = Int32Builder::new();
                let mut time = Int32Builder::new();
                match unit {
                    TimeUnit::Second => {
                        let array = batch
                            .column(*index)
                            .as_any()
                            .downcast_ref::<TimestampSecondArray>()
                            .expect("timestamp second downcast");
                        for i in 0..array.len() {
                            if array.is_null(i) {
                                year.append_null();
                                month.append_null();
                                day.append_null();
                                time.append_null();
                                continue;
                            }
                            let dt = as_datetime::<TimestampSecondType>(array.value(i))
                                .expect("timestamp second conversion");
                            year.append_value(dt.year() as i32);
                            month.append_value(dt.month() as i32);
                            day.append_value(dt.day() as i32);
                            time.append_value(dt.time().num_seconds_from_midnight() as i32);
                        }
                    }
                    TimeUnit::Millisecond => {
                        let array = batch
                            .column(*index)
                            .as_any()
                            .downcast_ref::<TimestampMillisecondArray>()
                            .expect("timestamp millisecond downcast");
                        for i in 0..array.len() {
                            if array.is_null(i) {
                                year.append_null();
                                month.append_null();
                                day.append_null();
                                time.append_null();
                                continue;
                            }
                            let dt = as_datetime::<TimestampMillisecondType>(array.value(i))
                                .expect("timestamp millisecond conversion");
                            year.append_value(dt.year() as i32);
                            month.append_value(dt.month() as i32);
                            day.append_value(dt.day() as i32);
                            time.append_value(dt.time().num_seconds_from_midnight() as i32);
                        }
                    }
                    TimeUnit::Microsecond => {
                        let array = batch
                            .column(*index)
                            .as_any()
                            .downcast_ref::<TimestampMicrosecondArray>()
                            .expect("timestamp microsecond downcast");
                        for i in 0..array.len() {
                            if array.is_null(i) {
                                year.append_null();
                                month.append_null();
                                day.append_null();
                                time.append_null();
                                continue;
                            }
                            let dt = as_datetime::<TimestampMicrosecondType>(array.value(i))
                                .expect("timestamp microsecond conversion");
                            year.append_value(dt.year() as i32);
                            month.append_value(dt.month() as i32);
                            day.append_value(dt.day() as i32);
                            time.append_value(dt.time().num_seconds_from_midnight() as i32);
                        }
                    }
                    TimeUnit::Nanosecond => {
                        let array = batch
                            .column(*index)
                            .as_any()
                            .downcast_ref::<TimestampNanosecondArray>()
                            .expect("timestamp nanosecond downcast");
                        for i in 0..array.len() {
                            if array.is_null(i) {
                                year.append_null();
                                month.append_null();
                                day.append_null();
                                time.append_null();
                                continue;
                            }
                            let dt = as_datetime::<TimestampNanosecondType>(array.value(i))
                                .expect("timestamp nanosecond conversion");
                            year.append_value(dt.year() as i32);
                            month.append_value(dt.month() as i32);
                            day.append_value(dt.day() as i32);
                            time.append_value(dt.time().num_seconds_from_midnight() as i32);
                        }
                    }
                }
                cols.push(Arc::new(year.finish()));
                cols.push(Arc::new(month.finish()));
                cols.push(Arc::new(day.finish()));
                cols.push(Arc::new(time.finish()));
            }
        }
    }

    RecordBatch::try_new(Arc::clone(out_schema), cols).expect("expanded batch build")
}

fn poneglyph_field(field: &Field) -> Field {
    match field.data_type() {
        DataType::Float32 | DataType::Float64 | DataType::Decimal128(_, _) => {
            Field::new(field.name(), DataType::UInt64, true)
        }
        _ => field.clone().with_nullable(true),
    }
}

fn decimalized_field(field: &Field) -> Field {
    match field.data_type() {
        DataType::Float32 | DataType::Float64 => Field::new(
            field.name(),
            DataType::Decimal128(NORMAL_DECIMAL_PRECISION, NORMAL_DECIMAL_SCALE),
            true,
        ),
        _ => field.clone().with_nullable(true),
    }
}

fn decimalized_schema(schema: &Schema) -> Arc<Schema> {
    Arc::new(Schema::new(
        schema
            .fields()
            .iter()
            .map(|f| decimalized_field(f))
            .collect::<Vec<_>>(),
    ))
}

fn scaled_decimal128(value: f64, precision: u8, scale: i8) -> Option<i128> {
    if !value.is_finite() {
        return None;
    }

    let scaled = (value * 10_f64.powi(i32::from(scale))).round();
    if !scaled.is_finite() || scaled < i128::MIN as f64 || scaled > i128::MAX as f64 {
        return None;
    }

    let scaled = scaled as i128;
    let max_value = 10_i128.pow(u32::from(precision)) - 1;
    if scaled.unsigned_abs() > max_value as u128 {
        None
    } else {
        Some(scaled)
    }
}

fn convert_batch_to_decimalized(batch: &RecordBatch, out_schema: &Arc<Schema>) -> RecordBatch {
    let cols: Vec<ArrayRef> = batch
        .columns()
        .iter()
        .zip(batch.schema().fields().iter())
        .map(|(col, field)| match field.data_type() {
            DataType::Float32 => {
                let arr = col
                    .as_any()
                    .downcast_ref::<Float32Array>()
                    .expect("float32 downcast");
                let values: Vec<Option<i128>> = (0..arr.len())
                    .map(|i| {
                        if arr.is_null(i) {
                            None
                        } else {
                            scaled_decimal128(
                                f64::from(arr.value(i)),
                                NORMAL_DECIMAL_PRECISION,
                                NORMAL_DECIMAL_SCALE,
                            )
                        }
                    })
                    .collect();
                Arc::new(
                    Decimal128Array::from(values)
                        .with_precision_and_scale(NORMAL_DECIMAL_PRECISION, NORMAL_DECIMAL_SCALE)
                        .expect("float32 decimal128 precision/scale"),
                )
            }
            DataType::Float64 => {
                let arr = col
                    .as_any()
                    .downcast_ref::<Float64Array>()
                    .expect("float64 downcast");
                let values: Vec<Option<i128>> = (0..arr.len())
                    .map(|i| {
                        if arr.is_null(i) {
                            None
                        } else {
                            scaled_decimal128(
                                arr.value(i),
                                NORMAL_DECIMAL_PRECISION,
                                NORMAL_DECIMAL_SCALE,
                            )
                        }
                    })
                    .collect();
                Arc::new(
                    Decimal128Array::from(values)
                        .with_precision_and_scale(NORMAL_DECIMAL_PRECISION, NORMAL_DECIMAL_SCALE)
                        .expect("float64 decimal128 precision/scale"),
                )
            }
            _ => col.clone(),
        })
        .collect();
    RecordBatch::try_new(Arc::clone(out_schema), cols).expect("decimalized batch build")
}

fn poneglyph_schema(schema: &Schema) -> Arc<Schema> {
    Arc::new(Schema::new(
        schema
            .fields()
            .iter()
            .map(|f| poneglyph_field(f))
            .collect::<Vec<_>>(),
    ))
}

fn convert_batch_to_poneglyph(batch: &RecordBatch, out_schema: &Arc<Schema>) -> RecordBatch {
    let cols: Vec<ArrayRef> = batch
        .columns()
        .iter()
        .zip(batch.schema().fields().iter())
        .map(|(col, field)| match field.data_type() {
            DataType::Float32 => {
                let arr = col
                    .as_any()
                    .downcast_ref::<Float32Array>()
                    .expect("float32 downcast");
                let mut builder = UInt64Builder::new();
                for i in 0..arr.len() {
                    if arr.is_null(i) {
                        builder.append_null();
                        continue;
                    }
                    let scaled = f64::from(arr.value(i)) * 1000.0;
                    // Saturating: a negative value is 0, as the column is unsigned.
                    builder.append_value(scaled as u64);
                }
                Arc::new(builder.finish())
            }
            DataType::Float64 => {
                let arr = col
                    .as_any()
                    .downcast_ref::<Float64Array>()
                    .expect("float64 downcast");
                let mut builder = UInt64Builder::new();
                for i in 0..arr.len() {
                    if arr.is_null(i) {
                        builder.append_null();
                        continue;
                    }
                    let scaled = arr.value(i) * 1000.0;
                    // Saturating: a negative value is 0, as the column is unsigned.
                    builder.append_value(scaled as u64);
                }
                Arc::new(builder.finish())
            }
            DataType::Decimal128(_, _) => {
                let arr = col
                    .as_any()
                    .downcast_ref::<Decimal128Array>()
                    .expect("decimal128 downcast");
                let mut builder = UInt64Builder::new();
                for i in 0..arr.len() {
                    if arr.is_null(i) {
                        builder.append_null();
                        continue;
                    }
                    // A negative value is 0, as the column is unsigned.
                    builder.append_value(arr.value(i).clamp(0, u64::MAX as i128) as u64);
                }
                Arc::new(builder.finish())
            }
            _ => col.clone(),
        })
        .collect();
    RecordBatch::try_new(Arc::clone(out_schema), cols).expect("poneglyph batch build")
}

/// Write the batches as Parquet in the shape the prover reads: each date
/// or timestamp column followed by its year, month, day (and time) parts,
/// `Float32`/`Float64` columns as `Decimal128(18, 3)`, a `__row_id__`
/// column numbering the rows, and an `__activator__` column. Null rows
/// with `__activator__ = false` pad the row count to a power of two.
fn write_parquet<P: AsRef<Path>>(
    path: P,
    orig_schema: &arrow::datatypes::SchemaRef,
    batches: impl Iterator<Item = RecordBatch>,
) {
    let path_ref = path.as_ref();
    if let Some(parent) = path_ref.parent() {
        create_dir_all(parent).expect("create output dir");
    }

    let (expansions, expanded_fields) = build_expansions(orig_schema.as_ref());
    let expanded_schema = Arc::new(Schema::new(expanded_fields));
    let decimalized_base_schema = decimalized_schema(expanded_schema.as_ref());

    let mut fields: Vec<Field> = decimalized_base_schema
        .fields()
        .iter()
        .map(|f| (**f).clone())
        .collect();
    fields.push(Field::new(ROW_ID_COL_NAME, DataType::Int64, false));
    fields.push(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false));
    let out_schema = Arc::new(Schema::new(fields));

    let file = File::create(path_ref).expect("create parquet file");
    let mut writer = ArrowWriter::try_new(file, Arc::clone(&out_schema), None).expect("new writer");

    let mut total_rows: usize = 0;
    let mut next_row_id: i64 = 0;
    let mut last_nonempty_batch: Option<RecordBatch> = None;

    for batch in batches {
        let n = batch.num_rows();
        if n == 0 {
            continue;
        }
        let batch = expand_batch(&batch, &expansions, &expanded_schema);
        let batch = convert_batch_to_decimalized(&batch, &decimalized_base_schema);
        total_rows += n;
        last_nonempty_batch = Some(batch.clone());

        // Row ids continue across batches.
        let mut row_id_builder = Int64Builder::new();
        for offset in 0..n {
            row_id_builder.append_value(next_row_id + offset as i64);
        }
        next_row_id += n as i64;
        let row_id = Arc::new(row_id_builder.finish());

        let mut act_builder = BooleanBuilder::new();
        for _ in 0..n {
            act_builder.append_value(true);
        }
        let activator = Arc::new(act_builder.finish());

        let mut cols = batch.columns().to_vec();
        cols.push(row_id);
        cols.push(activator);
        let out_batch = RecordBatch::try_new(Arc::clone(&out_schema), cols)
            .expect("rebuild batch with activator");
        writer.write(&out_batch).expect("write batch");
    }

    if total_rows == 0 {
        writer.close().expect("close writer");
        return;
    }

    if !total_rows.is_power_of_two() {
        let target = total_rows.next_power_of_two();
        let pad = target - total_rows;
        let last_batch = last_nonempty_batch.expect("must have last batch");

        // Padding rows are null in every data column and inactive.
        let mut pad_cols = Vec::with_capacity(last_batch.num_columns() + 2);
        for col in last_batch.columns() {
            pad_cols.push(new_null_array(col.data_type(), pad));
        }

        let mut row_id_builder = Int64Builder::new();
        for offset in 0..pad {
            row_id_builder.append_value(next_row_id + offset as i64);
        }
        let pad_row_id = Arc::new(row_id_builder.finish());
        pad_cols.push(pad_row_id);

        let mut act_builder = BooleanBuilder::new();
        for _ in 0..pad {
            act_builder.append_value(false);
        }
        let pad_activator = Arc::new(act_builder.finish());
        pad_cols.push(pad_activator);

        let pad_batch =
            RecordBatch::try_new(Arc::clone(&out_schema), pad_cols).expect("pad batch build");
        writer.write(&pad_batch).expect("write pad batch");
    }

    writer.close().expect("close writer");
}

/// [`write_parquet`] with floating-point and decimal columns as `UInt64`
/// instead of `Decimal128`.
fn write_parquet_poneglyph<P: AsRef<Path>>(
    path: P,
    orig_schema: &arrow::datatypes::SchemaRef,
    batches: impl Iterator<Item = RecordBatch>,
) {
    let path_ref = path.as_ref();
    if let Some(parent) = path_ref.parent() {
        create_dir_all(parent).expect("create output dir");
    }

    let (expansions, expanded_fields) = build_expansions(orig_schema.as_ref());
    let expanded_schema = Arc::new(Schema::new(expanded_fields));
    let poneglyph_base_schema = poneglyph_schema(expanded_schema.as_ref());

    let mut fields: Vec<Field> = poneglyph_base_schema
        .fields()
        .iter()
        .map(|f| (**f).clone())
        .collect();
    fields.push(Field::new(ROW_ID_COL_NAME, DataType::Int64, false));
    fields.push(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false));
    let out_schema = Arc::new(Schema::new(fields));

    let file = File::create(path_ref).expect("create parquet file");
    let mut writer = ArrowWriter::try_new(file, Arc::clone(&out_schema), None).expect("new writer");

    let mut total_rows: usize = 0;
    let mut next_row_id: i64 = 0;
    let mut last_nonempty_batch: Option<RecordBatch> = None;

    for batch in batches {
        let n = batch.num_rows();
        if n == 0 {
            continue;
        }
        let batch = expand_batch(&batch, &expansions, &expanded_schema);
        let batch = convert_batch_to_poneglyph(&batch, &poneglyph_base_schema);
        total_rows += n;
        last_nonempty_batch = Some(batch.clone());

        let mut row_id_builder = Int64Builder::new();
        for offset in 0..n {
            row_id_builder.append_value(next_row_id + offset as i64);
        }
        next_row_id += n as i64;
        let row_id = Arc::new(row_id_builder.finish());

        let mut act_builder = BooleanBuilder::new();
        for _ in 0..n {
            act_builder.append_value(true);
        }
        let activator = Arc::new(act_builder.finish());

        let mut cols = batch.columns().to_vec();
        cols.push(row_id);
        cols.push(activator);
        let out_batch = RecordBatch::try_new(Arc::clone(&out_schema), cols)
            .expect("rebuild batch with activator");
        writer.write(&out_batch).expect("write batch");
    }

    if total_rows == 0 {
        writer.close().expect("close writer");
        return;
    }

    if !total_rows.is_power_of_two() {
        let target = total_rows.next_power_of_two();
        let pad = target - total_rows;
        let last_batch = last_nonempty_batch.expect("must have last batch");

        let mut pad_cols = Vec::with_capacity(last_batch.num_columns() + 2);
        for col in last_batch.columns() {
            pad_cols.push(new_null_array(col.data_type(), pad));
        }

        let mut row_id_builder = Int64Builder::new();
        for offset in 0..pad {
            row_id_builder.append_value(next_row_id + offset as i64);
        }
        let pad_row_id = Arc::new(row_id_builder.finish());
        pad_cols.push(pad_row_id);

        let mut act_builder = BooleanBuilder::new();
        for _ in 0..pad {
            act_builder.append_value(false);
        }
        let pad_activator = Arc::new(act_builder.finish());
        pad_cols.push(pad_activator);

        let pad_batch =
            RecordBatch::try_new(Arc::clone(&out_schema), pad_cols).expect("pad batch build");
        writer.write(&pad_batch).expect("write pad batch");
    }

    writer.close().expect("close writer");
}

/// Write the batches as Parquet with the date and timestamp parts added,
/// but no system columns and no padding.
fn write_parquet_raw<P: AsRef<Path>>(
    path: P,
    orig_schema: &arrow::datatypes::SchemaRef,
    batches: impl Iterator<Item = RecordBatch>,
) {
    let path_ref = path.as_ref();
    if let Some(parent) = path_ref.parent() {
        create_dir_all(parent).expect("create output dir");
    }

    let (expansions, expanded_fields) = build_expansions(orig_schema.as_ref());
    let out_schema = Arc::new(Schema::new(expanded_fields));
    let file = File::create(path_ref).expect("create parquet file");
    let mut writer = ArrowWriter::try_new(file, Arc::clone(&out_schema), None).expect("new writer");

    for batch in batches {
        if batch.num_rows() == 0 {
            continue;
        }
        let expanded = expand_batch(&batch, &expansions, &out_schema);
        writer.write(&expanded).expect("write batch");
    }

    writer.close().expect("close writer");
}

/// Generate the TPC-H tables at scale factor `scale` as Parquet files in
/// `out_dir` (created if missing), each with system columns and padding
/// ([`write_parquet`]). Also writes the raw tables to a sibling
/// `orig-<dir>` directory, the `<table>_poneglyph` variants and
/// `constraints.json`.
pub fn generate_parquet_scale<P: AsRef<Path>>(scale: f64, out_dir: P) {
    let out = out_dir.as_ref();

    // Each generator takes (scale, part, step); part = 1 and step = 1
    // generate the whole table on one thread.

    // nation
    {
        let generator = NationGenerator::new(scale, 1, 1);
        let mut it = NationArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        let generator_raw = NationGenerator::new(scale, 1, 1);
        let mut it_raw = NationArrow::new(generator_raw).with_batch_size(DEFAULT_BATCH_SIZE);
        let generator_poneglyph = NationGenerator::new(FIXED_PONEGLYPH_SCALE, 1, 1);
        let mut it_poneglyph =
            NationArrow::new(generator_poneglyph).with_batch_size(DEFAULT_BATCH_SIZE);
        let orig_out = out.with_file_name(format!(
            "orig-{}",
            out.file_name().unwrap_or_default().to_string_lossy()
        ));
        write_parquet_raw(orig_out.join("nation.parquet"), &schema, &mut it_raw);
        write_parquet(out.join("nation.parquet"), &schema, &mut it);
        write_parquet_poneglyph(
            out.join("nation_poneglyph.parquet"),
            &schema,
            &mut it_poneglyph,
        );
    }
    // region
    {
        let generator = RegionGenerator::new(scale, 1, 1);
        let mut it = RegionArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        let generator_raw = RegionGenerator::new(scale, 1, 1);
        let mut it_raw = RegionArrow::new(generator_raw).with_batch_size(DEFAULT_BATCH_SIZE);
        let generator_poneglyph = RegionGenerator::new(FIXED_PONEGLYPH_SCALE, 1, 1);
        let mut it_poneglyph =
            RegionArrow::new(generator_poneglyph).with_batch_size(DEFAULT_BATCH_SIZE);
        let orig_out = out.with_file_name(format!(
            "orig-{}",
            out.file_name().unwrap_or_default().to_string_lossy()
        ));
        write_parquet_raw(orig_out.join("region.parquet"), &schema, &mut it_raw);
        write_parquet(out.join("region.parquet"), &schema, &mut it);
        write_parquet_poneglyph(
            out.join("region_poneglyph.parquet"),
            &schema,
            &mut it_poneglyph,
        );
    }
    // part
    {
        let generator = PartGenerator::new(scale, 1, 1);
        let mut it = PartArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        let generator_raw = PartGenerator::new(scale, 1, 1);
        let mut it_raw = PartArrow::new(generator_raw).with_batch_size(DEFAULT_BATCH_SIZE);
        let generator_poneglyph = PartGenerator::new(FIXED_PONEGLYPH_SCALE, 1, 1);
        let mut it_poneglyph =
            PartArrow::new(generator_poneglyph).with_batch_size(DEFAULT_BATCH_SIZE);
        let orig_out = out.with_file_name(format!(
            "orig-{}",
            out.file_name().unwrap_or_default().to_string_lossy()
        ));
        write_parquet_raw(orig_out.join("part.parquet"), &schema, &mut it_raw);
        write_parquet(out.join("part.parquet"), &schema, &mut it);
        write_parquet_poneglyph(
            out.join("part_poneglyph.parquet"),
            &schema,
            &mut it_poneglyph,
        );
    }
    // supplier
    {
        let generator = SupplierGenerator::new(scale, 1, 1);
        let mut it = SupplierArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        let generator_raw = SupplierGenerator::new(scale, 1, 1);
        let mut it_raw = SupplierArrow::new(generator_raw).with_batch_size(DEFAULT_BATCH_SIZE);
        let generator_poneglyph = SupplierGenerator::new(FIXED_PONEGLYPH_SCALE, 1, 1);
        let mut it_poneglyph =
            SupplierArrow::new(generator_poneglyph).with_batch_size(DEFAULT_BATCH_SIZE);
        let orig_out = out.with_file_name(format!(
            "orig-{}",
            out.file_name().unwrap_or_default().to_string_lossy()
        ));
        write_parquet_raw(orig_out.join("supplier.parquet"), &schema, &mut it_raw);
        write_parquet(out.join("supplier.parquet"), &schema, &mut it);
        write_parquet_poneglyph(
            out.join("supplier_poneglyph.parquet"),
            &schema,
            &mut it_poneglyph,
        );
    }
    // partsupp
    {
        let generator = PartSuppGenerator::new(scale, 1, 1);
        let mut it = PartSuppArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        let generator_raw = PartSuppGenerator::new(scale, 1, 1);
        let mut it_raw = PartSuppArrow::new(generator_raw).with_batch_size(DEFAULT_BATCH_SIZE);
        let generator_poneglyph = PartSuppGenerator::new(FIXED_PONEGLYPH_SCALE, 1, 1);
        let mut it_poneglyph =
            PartSuppArrow::new(generator_poneglyph).with_batch_size(DEFAULT_BATCH_SIZE);
        let orig_out = out.with_file_name(format!(
            "orig-{}",
            out.file_name().unwrap_or_default().to_string_lossy()
        ));
        write_parquet_raw(orig_out.join("partsupp.parquet"), &schema, &mut it_raw);
        write_parquet(out.join("partsupp.parquet"), &schema, &mut it);
        write_parquet_poneglyph(
            out.join("partsupp_poneglyph.parquet"),
            &schema,
            &mut it_poneglyph,
        );
    }
    // customer
    {
        let generator = CustomerGenerator::new(scale, 1, 1);
        let mut it = CustomerArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        let generator_raw = CustomerGenerator::new(scale, 1, 1);
        let mut it_raw = CustomerArrow::new(generator_raw).with_batch_size(DEFAULT_BATCH_SIZE);
        let generator_poneglyph = CustomerGenerator::new(FIXED_PONEGLYPH_SCALE, 1, 1);
        let mut it_poneglyph =
            CustomerArrow::new(generator_poneglyph).with_batch_size(DEFAULT_BATCH_SIZE);
        let orig_out = out.with_file_name(format!(
            "orig-{}",
            out.file_name().unwrap_or_default().to_string_lossy()
        ));
        write_parquet_raw(orig_out.join("customer.parquet"), &schema, &mut it_raw);
        write_parquet(out.join("customer.parquet"), &schema, &mut it);
        write_parquet_poneglyph(
            out.join("customer_poneglyph.parquet"),
            &schema,
            &mut it_poneglyph,
        );
    }
    // orders
    {
        let generator = OrderGenerator::new(scale, 1, 1);
        let mut it = OrderArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        let generator_raw = OrderGenerator::new(scale, 1, 1);
        let mut it_raw = OrderArrow::new(generator_raw).with_batch_size(DEFAULT_BATCH_SIZE);
        let generator_poneglyph = OrderGenerator::new(FIXED_PONEGLYPH_SCALE, 1, 1);
        let mut it_poneglyph =
            OrderArrow::new(generator_poneglyph).with_batch_size(DEFAULT_BATCH_SIZE);
        let orig_out = out.with_file_name(format!(
            "orig-{}",
            out.file_name().unwrap_or_default().to_string_lossy()
        ));
        write_parquet_raw(orig_out.join("orders.parquet"), &schema, &mut it_raw);
        write_parquet(out.join("orders.parquet"), &schema, &mut it);
        write_parquet_poneglyph(
            out.join("orders_poneglyph.parquet"),
            &schema,
            &mut it_poneglyph,
        );
    }
    // lineitem
    {
        let generator = LineItemGenerator::new(scale, 1, 1);
        let mut it = LineItemArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        let generator_raw = LineItemGenerator::new(scale, 1, 1);
        let mut it_raw = LineItemArrow::new(generator_raw).with_batch_size(DEFAULT_BATCH_SIZE);
        let generator_poneglyph = LineItemGenerator::new(FIXED_PONEGLYPH_SCALE, 1, 1);
        let mut it_poneglyph =
            LineItemArrow::new(generator_poneglyph).with_batch_size(DEFAULT_BATCH_SIZE);
        let orig_out = out.with_file_name(format!(
            "orig-{}",
            out.file_name().unwrap_or_default().to_string_lossy()
        ));
        write_parquet_raw(orig_out.join("lineitem.parquet"), &schema, &mut it_raw);
        write_parquet(out.join("lineitem.parquet"), &schema, &mut it);
        write_parquet_poneglyph(
            out.join("lineitem_poneglyph.parquet"),
            &schema,
            &mut it_poneglyph,
        );
    }

    write_constraints_manifest(out);
}

/// Rewrite an existing Parquet file in the shape [`write_parquet`]
/// produces.
pub fn preprocess_parquet<P: AsRef<Path>>(
    input: P,
    output: P,
) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(input.as_ref())?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let schema = Arc::clone(builder.schema());
    let reader = builder.build()?;
    write_parquet(
        output,
        &schema,
        reader.into_iter().map(|batch| batch.expect("read batch")),
    );
    Ok(())
}

/// Absolute path of `file` under the workspace's `artifacts/test-data`.
pub fn test_data_path(file: impl AsRef<Path>) -> PathBuf {
    workspace_artifacts_dir().join("test-data").join(file)
}

/// Absolute path of `file` under the workspace's `artifacts/bench-data`.
pub fn bench_data_path(file: impl AsRef<Path>) -> PathBuf {
    workspace_artifacts_dir().join("bench-data").join(file)
}

#[derive(Clone, Copy, Debug)]
pub struct TpchQuerySpec {
    pub sql: &'static str,
    pub tables: &'static [&'static str],
}

fn fetch_tpch_query_sql(number: u8) -> String {
    let conn = Connection::open_in_memory().expect("open in-memory DuckDB");
    conn.execute("INSTALL tpch", [])
        .expect("install DuckDB tpch extension");
    conn.execute("LOAD tpch", [])
        .expect("load DuckDB tpch extension");
    let mut stmt = conn
        .prepare("SELECT query FROM tpch_queries() WHERE query_nr = ?")
        .expect("prepare tpch query fetch");
    let mut rows = stmt
        .query([number as i64])
        .expect("execute tpch query fetch");
    let row = rows
        .next()
        .expect("fetch tpch query row")
        .unwrap_or_else(|| panic!("TPC-H query {number} not found"));
    let sql = row
        .get::<_, String>(0)
        .expect("extract tpch query SQL text");
    normalize_tpch_sql(number, sql)
}

fn normalize_tpch_sql(number: u8, sql: String) -> String {
    if number == 8 || number == 9 {
        // DataFusion does not plan EXTRACT(YEAR FROM ...): use date_part.
        let needle = "extract(year from";
        let lower = sql.to_ascii_lowercase();
        let mut out = String::with_capacity(sql.len());
        let mut i = 0;
        while let Some(pos) = lower[i..].find(needle) {
            let start = i + pos;
            out.push_str(&sql[i..start]);
            out.push_str("date_part('year',");
            i = start + needle.len();
        }
        out.push_str(&sql[i..]);
        out
    } else {
        sql
    }
}

static TPCH_Q1_TT_2_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q3_TT_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q5_TT_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q6_TT_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q10_TT_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q11_TT_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q12_TT_2_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q18_TT_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q19_TT_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q21_TT_SQL: OnceLock<&'static str> = OnceLock::new();

// Q1 without its string ORDER BY keys.
const TPCH_Q1_TT_SQL: &str = r#"
SELECT
    l_returnflag,
    l_linestatus,
    sum(l_quantity) AS sum_qty,
    sum(l_extendedprice) AS sum_base_price,
    sum(l_extendedprice * (1 - l_discount)) AS sum_disc_price,
    sum(l_extendedprice * (1 - l_discount) * (1 + l_tax)) AS sum_charge,
    avg(l_quantity) AS avg_qty,
    avg(l_extendedprice) AS avg_price,
    avg(l_discount) AS avg_disc,
    count(*) AS count_order
FROM
    lineitem
WHERE
    l_shipdate <= CAST('1998-09-02' AS date)
GROUP BY
    l_returnflag,
    l_linestatus;
"#;

// Q12 without its string ORDER BY key.
const TPCH_Q12_TT_SQL: &str = r#"
SELECT
    l_shipmode,
    sum(
        CASE WHEN o_orderpriority = '1-URGENT'
            OR o_orderpriority = '2-HIGH' THEN
            1
        ELSE
            0
        END) AS high_line_count,
    sum(
        CASE WHEN o_orderpriority <> '1-URGENT'
            AND o_orderpriority <> '2-HIGH' THEN
            1
        ELSE
            0
        END) AS low_line_count
FROM
    orders,
    lineitem
WHERE
    o_orderkey = l_orderkey
    AND l_shipmode IN ('MAIL', 'SHIP')
    AND l_commitdate < l_receiptdate
    AND l_shipdate < l_commitdate
    AND l_receiptdate >= CAST('1994-01-01' AS date)
    AND l_receiptdate < CAST('1995-01-01' AS date)
GROUP BY
    l_shipmode;
"#;

const TPCH_Q1_PGN_SQL: &str = r#"
SELECT
    l_returnflag,
    sum(l_quantity) AS sum_qty,
    sum(l_extendedprice) AS sum_base_price,
    sum(l_extendedprice * (1 - l_discount)) AS sum_disc_price,
    sum(l_extendedprice * (1 - l_discount) * (1 + l_tax)) AS sum_charge,
    count(*) AS count_order
FROM
    lineitem_poneglyph
WHERE
    l_shipdate <= CAST('1998-09-02' AS date)
GROUP BY
    l_returnflag
ORDER BY
    l_returnflag
"#;

// Q2 without its LIKE and its string ORDER BY keys.
const TPCH_Q2_TT_SQL: &str = r#"
SELECT
    s_acctbal,
    s_name,
    n_name,
    p_partkey,
    p_mfgr,
    s_address,
    s_phone,
    s_comment
FROM
    part,
    supplier,
    partsupp,
    nation,
    region
WHERE
    p_partkey = ps_partkey
    AND s_suppkey = ps_suppkey
    AND p_size = 15
    AND s_nationkey = n_nationkey
    AND n_regionkey = r_regionkey
    AND r_name = 'EUROPE'
    AND ps_supplycost = (
        SELECT
            min(ps_supplycost)
        FROM
            partsupp,
            supplier,
            nation,
            region
        WHERE
            p_partkey = ps_partkey
            AND s_suppkey = ps_suppkey
            AND s_nationkey = n_nationkey
            AND n_regionkey = r_regionkey
            AND r_name = 'EUROPE')
ORDER BY
    s_acctbal DESC,
    p_partkey
LIMIT 100;
"#;

// Q2 with its LIKE, the official `p_type LIKE '%BRASS'`, and its string
// ORDER BY keys.
const TPCH_Q2_TT_2_SQL: &str = r#"
SELECT
    s_acctbal,
    s_name,
    n_name,
    p_partkey,
    p_mfgr,
    s_address,
    s_phone,
    s_comment
FROM
    part,
    supplier,
    partsupp,
    nation,
    region
WHERE
    p_partkey = ps_partkey
    AND s_suppkey = ps_suppkey
    AND p_size = 15
    AND p_type LIKE '%BRASS'
    AND s_nationkey = n_nationkey
    AND n_regionkey = r_regionkey
    AND r_name = 'EUROPE'
    AND ps_supplycost = (
        SELECT
            min(ps_supplycost)
        FROM
            partsupp,
            supplier,
            nation,
            region
        WHERE
            p_partkey = ps_partkey
            AND s_suppkey = ps_suppkey
            AND s_nationkey = n_nationkey
            AND n_regionkey = r_regionkey
            AND r_name = 'EUROPE')
ORDER BY
    s_acctbal DESC,
    n_name,
    s_name,
    p_partkey
LIMIT 100;
"#;

// Q7 without its string ORDER BY keys.
const TPCH_Q7_TT_SQL: &str = r#"
SELECT
    supp_nation,
    cust_nation,
    l_year,
    sum(volume) AS revenue
FROM (
    SELECT
        n1.n_name AS supp_nation,
        n2.n_name AS cust_nation,
        l_shipdate_year AS l_year,
        l_extendedprice * (1 - l_discount) AS volume
    FROM
        supplier,
        lineitem,
        orders,
        customer,
        nation n1,
        nation n2
    WHERE
        s_suppkey = l_suppkey
        AND o_orderkey = l_orderkey
        AND c_custkey = o_custkey
        AND s_nationkey = n1.n_nationkey
        AND c_nationkey = n2.n_nationkey
        AND ((n1.n_name = 'FRANCE'
                AND n2.n_name = 'GERMANY')
            OR (n1.n_name = 'GERMANY'
                AND n2.n_name = 'FRANCE'))
        AND l_shipdate BETWEEN CAST('1995-01-01' AS date)
        AND CAST('1996-12-31' AS date)) AS shipping
GROUP BY
    supp_nation,
    cust_nation,
    l_year
ORDER BY
    l_year;
"#;

// Q7 with its string ORDER BY keys.
const TPCH_Q7_TT_2_SQL: &str = r#"
SELECT
    supp_nation,
    cust_nation,
    l_year,
    sum(volume) AS revenue
FROM (
    SELECT
        n1.n_name AS supp_nation,
        n2.n_name AS cust_nation,
        l_shipdate_year AS l_year,
        l_extendedprice * (1 - l_discount) AS volume
    FROM
        supplier,
        lineitem,
        orders,
        customer,
        nation n1,
        nation n2
    WHERE
        s_suppkey = l_suppkey
        AND o_orderkey = l_orderkey
        AND c_custkey = o_custkey
        AND s_nationkey = n1.n_nationkey
        AND c_nationkey = n2.n_nationkey
        AND ((n1.n_name = 'FRANCE'
                AND n2.n_name = 'GERMANY')
            OR (n1.n_name = 'GERMANY'
                AND n2.n_name = 'FRANCE'))
        AND l_shipdate BETWEEN CAST('1995-01-01' AS date)
        AND CAST('1996-12-31' AS date)) AS shipping
GROUP BY
    supp_nation,
    cust_nation,
    l_year
ORDER BY
    supp_nation,
    cust_nation,
    l_year;
"#;

const TPCH_Q13_TT_SQL: &str = r#"
SELECT
    c_count,
    count(*) AS custdist
FROM (
    SELECT
        c_custkey,
        count(o_orderkey)
    FROM
        customer
    LEFT OUTER JOIN orders ON c_custkey = o_custkey
GROUP BY
    c_custkey) AS c_orders (c_custkey,
        c_count)
GROUP BY
    c_count
ORDER BY
    custdist DESC,
    c_count DESC;
"#;

const TPCH_Q14_TT_SQL: &str = r#"
SELECT
    CAST(100.00 AS DECIMAL(15, 2)) * sum(l_extendedprice * (1 - l_discount))
        / sum(l_extendedprice * (1 - l_discount)) AS promo_revenue
FROM
    lineitem,
    part
WHERE
    l_partkey = p_partkey
    AND l_shipdate >= date '1995-09-01'
    AND l_shipdate < CAST('1995-10-01' AS date);
"#;

// Q14 with the official `p_type LIKE 'PROMO%'`, evaluated in a projection
// over the `part` scan: a LIKE reads the characters only its scan carries.
const TPCH_Q14_TT_2_SQL: &str = r#"
SELECT
    CAST(100.00 AS DECIMAL(15, 2)) * sum(
        CASE WHEN promo THEN
            l_extendedprice * (1 - l_discount)
        ELSE
            0
        END) / sum(l_extendedprice * (1 - l_discount)) AS promo_revenue
FROM
    lineitem,
    (
        SELECT
            p_partkey,
            p_type LIKE 'PROMO%' AS promo
        FROM
            part) AS promo_part
WHERE
    l_partkey = p_partkey
    AND l_shipdate >= date '1995-09-01'
    AND l_shipdate < CAST('1995-10-01' AS date);
"#;

// Q4 without its string ORDER BY key.
const TPCH_Q4_TT_SQL: &str = r#"
SELECT
    o_orderpriority,
    count(*) AS order_count
FROM
    orders
INNER JOIN (
    SELECT
        l_orderkey
    FROM
        lineitem
    WHERE
        l_receiptdate > l_commitdate
    GROUP BY
        l_orderkey
) AS late_orders ON o_orderkey = l_orderkey
WHERE
    o_orderdate >= CAST('1993-07-01' AS date)
    AND o_orderdate < CAST('1993-10-01' AS date)
GROUP BY
    o_orderpriority;
"#;

// Q4 with its string ORDER BY key.
const TPCH_Q4_TT_2_SQL: &str = r#"
SELECT
    o_orderpriority,
    count(*) AS order_count
FROM
    orders
INNER JOIN (
    SELECT
        l_orderkey
    FROM
        lineitem
    WHERE
        l_receiptdate > l_commitdate
    GROUP BY
        l_orderkey
) AS late_orders ON o_orderkey = l_orderkey
WHERE
    o_orderdate >= CAST('1993-07-01' AS date)
    AND o_orderdate < CAST('1993-10-01' AS date)
GROUP BY
    o_orderpriority
ORDER BY
    o_orderpriority;
"#;

const TPCH_Q15_TT_SQL: &str = r#"
WITH revenue AS (
    SELECT
        l_suppkey AS supplier_no,
        sum(l_extendedprice * (1 - l_discount)) AS total_revenue
    FROM
        lineitem
    WHERE
        l_shipdate >= CAST('1996-01-01' AS date)
        AND l_shipdate < CAST('1996-04-01' AS date)
    GROUP BY
        supplier_no
),
max_revenue AS (
    SELECT
        max(total_revenue) AS highest_val
    FROM
        revenue
)
SELECT
    s_suppkey,
    s_name,
    s_address,
    s_phone,
    total_revenue
FROM
    supplier
INNER JOIN revenue
    ON s_suppkey = supplier_no
INNER JOIN max_revenue
    ON total_revenue = highest_val
ORDER BY
    s_suppkey;
"#;

const TPCH_Q16_TT_SQL: &str = r#"
SELECT
    p_brand,
    p_type,
    p_size,
    count(DISTINCT ps_suppkey) AS supplier_cnt
FROM
    partsupp,
    part
WHERE
    p_partkey = ps_partkey
    AND p_brand <> 'Brand#45'
    AND p_size IN (49, 14, 23, 45, 19, 3, 36, 9)
    AND ps_suppkey NOT IN (
        SELECT
            s_suppkey
        FROM
            supplier)
GROUP BY
    p_brand,
    p_type,
    p_size
ORDER BY
    supplier_cnt DESC,
    p_brand,
    p_type,
    p_size;
"#;

const TPCH_Q17_TT_SQL: &str = r#"
SELECT
    sum(l_extendedprice) / CAST(7.0 AS DECIMAL(15, 2)) AS avg_yearly
FROM
    lineitem,
    part
WHERE
    p_partkey = l_partkey
    AND p_brand = 'Brand#23'
    AND p_container = 'MED BOX'
    AND l_quantity < (
        SELECT
            CAST(0.2 AS DECIMAL(15, 2)) * avg(l_quantity)
        FROM
            lineitem
        WHERE
            l_partkey = p_partkey);
"#;

// Q20 flattened to inner joins, so that it goes through the join gadget
// like the other rewritten subquery queries and not through
// planner-generated semi-joins with null right-side provenance; without its
// LIKE and its string ORDER BY key.
const TPCH_Q20_TT_SQL: &str = r#"
SELECT
    s_name,
    s_address
FROM
    supplier
INNER JOIN nation
    ON s_nationkey = n_nationkey
INNER JOIN (
    SELECT
        ps_suppkey
    FROM
        partsupp
    INNER JOIN part
        ON ps_partkey = p_partkey
    INNER JOIN (
        SELECT
            l_partkey,
            l_suppkey,
            CAST(0.5 AS DECIMAL(15, 2)) * sum(l_quantity) AS half_sum_qty
        FROM
            lineitem
        WHERE
            l_shipdate >= CAST('1994-01-01' AS date)
            AND l_shipdate < CAST('1995-01-01' AS date)
        GROUP BY
            l_partkey,
            l_suppkey
    ) AS lineitem_half_sum
        ON ps_partkey = l_partkey
        AND ps_suppkey = l_suppkey
    WHERE
        ps_availqty > half_sum_qty
    GROUP BY
        ps_suppkey
) AS candidate_suppliers
    ON s_suppkey = ps_suppkey
WHERE
    n_name = 'CANADA';
"#;

// Q20 with its LIKE, the official `p_name LIKE 'forest%'`, and its string
// ORDER BY key.
const TPCH_Q20_TT_2_SQL: &str = r#"
SELECT
    s_name,
    s_address
FROM
    supplier
INNER JOIN nation
    ON s_nationkey = n_nationkey
INNER JOIN (
    SELECT
        ps_suppkey
    FROM
        partsupp
    INNER JOIN part
        ON ps_partkey = p_partkey
    INNER JOIN (
        SELECT
            l_partkey,
            l_suppkey,
            CAST(0.5 AS DECIMAL(15, 2)) * sum(l_quantity) AS half_sum_qty
        FROM
            lineitem
        WHERE
            l_shipdate >= CAST('1994-01-01' AS date)
            AND l_shipdate < CAST('1995-01-01' AS date)
        GROUP BY
            l_partkey,
            l_suppkey
    ) AS lineitem_half_sum
        ON ps_partkey = l_partkey
        AND ps_suppkey = l_suppkey
    WHERE
        ps_availqty > half_sum_qty
        AND p_name LIKE 'forest%'
    GROUP BY
        ps_suppkey
) AS candidate_suppliers
    ON s_suppkey = ps_suppkey
WHERE
    n_name = 'CANADA'
ORDER BY
    s_name;
"#;

const TPCH_Q22_TT_SQL: &str = r#"
SELECT
    cntrycode,
    count(*) AS numcust,
    sum(c_acctbal) AS totacctbal
FROM (
    SELECT
        c_phone AS cntrycode,
        c_acctbal
    FROM
        customer
    WHERE
        c_phone IN ('13', '31', '23', '29', '30', '18', '17')
        AND
        c_acctbal > (
            SELECT
                avg(c_acctbal)
            FROM
                customer
            WHERE
                c_acctbal > 0.00
                AND c_phone IN ('13', '31', '23', '29', '30', '18', '17'))
        AND NOT EXISTS (
            SELECT
                *
            FROM
                orders
            WHERE
                o_custkey = c_custkey)) AS custsale
GROUP BY
    cntrycode
ORDER BY
    cntrycode;
"#;

const TPCH_Q3_PGN_SQL: &str = r#"
SELECT
    l_orderkey,
    sum(l_extendedprice * (1 - l_discount)) AS revenue,
    o_orderdate,
    o_shippriority
FROM
    customer_poneglyph,
    orders_poneglyph,
    lineitem_poneglyph
WHERE
    c_mktsegment = 'BUILDING'
    AND c_custkey = o_custkey
    AND l_orderkey = o_orderkey
    AND o_orderdate < CAST('1995-03-15' AS date)
    AND l_shipdate > CAST('1995-03-15' AS date)
GROUP BY
    l_orderkey,
    o_orderdate,
    o_shippriority
ORDER BY
    revenue DESC,
    o_orderdate
"#;

const TPCH_Q5_PGN_SQL: &str = r#"
SELECT
    n_name,
    sum(l_extendedprice * (1 - l_discount)) AS revenue
FROM
    customer_poneglyph,
    orders_poneglyph,
    lineitem_poneglyph,
    supplier_poneglyph,
    nation_poneglyph,
    region_poneglyph
WHERE
    c_custkey = o_custkey
    AND l_orderkey = o_orderkey
    AND l_suppkey = s_suppkey
    AND c_nationkey = s_nationkey
    AND s_nationkey = n_nationkey
    AND n_regionkey = r_regionkey
    AND r_name = 'ASIA'
    AND o_orderdate >= CAST('1994-01-01' AS date)
    AND o_orderdate < CAST('1995-01-01' AS date)
GROUP BY
    n_name
ORDER BY
    revenue DESC;
"#;

const TPCH_Q8_TT_SQL: &str = r#"
SELECT
    o_orderdate_year,
    sum(
        CASE WHEN nation = 'BRAZIL' THEN
            volume
        ELSE
            0
        END) AS mkt_share_num , sum(volume) AS mkt_share_denom
FROM (
    SELECT
        o_orderdate_year,
        l_extendedprice * (1 - l_discount) AS volume,
        n2.n_name AS nation
    FROM
        part,
        supplier,
        lineitem,
        orders,
        customer,
        nation n1,
        nation n2,
        region
    WHERE
        p_partkey = l_partkey
        AND s_suppkey = l_suppkey
        AND l_orderkey = o_orderkey
        AND o_custkey = c_custkey
        AND c_nationkey = n1.n_nationkey
        AND n1.n_regionkey = r_regionkey
        AND r_name = 'AMERICA'
        AND s_nationkey = n2.n_nationkey
        AND o_orderdate BETWEEN CAST('1995-01-01' AS date)
        AND CAST('1996-12-31' AS date)
        AND p_type = 'ECONOMY ANODIZED STEEL') AS all_nations
GROUP BY
    o_orderdate_year
ORDER BY
    o_orderdate_year;
"#;

const TPCH_Q8_PGN_SQL: &str = r#"
SELECT
    o_orderdate_year,
    sum(
        CASE WHEN nation = 'BRAZIL' THEN
            volume
        ELSE
            0
        END) AS mkt_share_num , sum(volume) AS mkt_share_denom
FROM (
    SELECT
        o_orderdate_year,
        l_extendedprice * (1 - l_discount) AS volume,
        n2.n_name AS nation
    FROM
        part_poneglyph,
        supplier_poneglyph,
        lineitem_poneglyph,
        orders_poneglyph,
        customer_poneglyph,
        nation_poneglyph n1,
        nation_poneglyph n2,
        region_poneglyph
    WHERE
        p_partkey = l_partkey
        AND s_suppkey = l_suppkey
        AND l_orderkey = o_orderkey
        AND o_custkey = c_custkey
        AND c_nationkey = n1.n_nationkey
        AND n1.n_regionkey = r_regionkey
        AND r_name = 'AMERICA'
        AND s_nationkey = n2.n_nationkey
        AND o_orderdate BETWEEN CAST('1995-01-01' AS date)
        AND CAST('1996-12-31' AS date)
        AND p_type = 'ECONOMY ANODIZED STEEL') AS all_nations
GROUP BY
    o_orderdate_year
ORDER BY
    o_orderdate_year;
"#;

// Q9 without its LIKE and its string ORDER BY key.
const TPCH_Q9_TT_SQL: &str = r#"
SELECT
    nation,
    o_orderdate_year,
    sum(amount) AS sum_profit
FROM (
    SELECT
        n_name AS nation,
        o_orderdate_year,
        l_extendedprice * (1 - l_discount) - ps_supplycost * l_quantity AS amount
    FROM
        part,
        supplier,
        lineitem,
        partsupp,
        orders,
        nation
    WHERE
        s_suppkey = l_suppkey
        AND ps_suppkey = l_suppkey
        AND ps_partkey = l_partkey
        AND p_partkey = l_partkey
        AND o_orderkey = l_orderkey
        AND s_nationkey = n_nationkey) AS profit
GROUP BY
    nation,
    o_orderdate_year
ORDER BY
    o_orderdate_year DESC;
"#;

// Q9 with its LIKE, the official `p_name LIKE '%green%'`, and its string
// ORDER BY key.
const TPCH_Q9_TT_2_SQL: &str = r#"
SELECT
    nation,
    o_orderdate_year,
    sum(amount) AS sum_profit
FROM (
    SELECT
        n_name AS nation,
        o_orderdate_year,
        l_extendedprice * (1 - l_discount) - ps_supplycost * l_quantity AS amount
    FROM
        part,
        supplier,
        lineitem,
        partsupp,
        orders,
        nation
    WHERE
        s_suppkey = l_suppkey
        AND ps_suppkey = l_suppkey
        AND ps_partkey = l_partkey
        AND p_partkey = l_partkey
        AND o_orderkey = l_orderkey
        AND s_nationkey = n_nationkey
        AND p_name LIKE '%green%') AS profit
GROUP BY
    nation,
    o_orderdate_year
ORDER BY
    nation,
    o_orderdate_year DESC;
"#;

const TPCH_Q9_PGN_SQL: &str = r#"
SELECT
    nation,
    o_orderdate_year,
    sum(amount) AS sum_profit
FROM (
    SELECT
        n_name AS nation,
        o_orderdate_year,
        l_extendedprice * (1 - l_discount) - ps_supplycost * l_quantity AS amount
    FROM
        part_poneglyph,
        supplier_poneglyph,
        lineitem_poneglyph,
        partsupp_poneglyph,
        orders_poneglyph,
        nation_poneglyph
    WHERE
        s_suppkey = l_suppkey
        AND ps_suppkey = l_suppkey
        AND ps_partkey = l_partkey
        AND p_partkey = l_partkey
        AND o_orderkey = l_orderkey
        AND s_nationkey = n_nationkey) AS profit
GROUP BY
    nation,
    o_orderdate_year
ORDER BY
    nation,
    o_orderdate_year DESC;
"#;

const TPCH_Q18_PGN_SQL: &str = r#"
SELECT
    c_name,
    c_custkey,
    o_orderkey,
    o_orderdate,
    o_totalprice,
    SUM(l_quantity) AS sum_l_quantity
FROM customer_poneglyph
JOIN orders_poneglyph   ON c_custkey = o_custkey
JOIN lineitem_poneglyph ON o_orderkey = l_orderkey
GROUP BY
    c_name,
    c_custkey,
    o_orderkey,
    o_orderdate,
    o_totalprice
ORDER BY
    o_totalprice DESC,
    o_orderdate ASC;
"#;

fn cached_tpch_sql(lock: &'static OnceLock<&'static str>, number: u8) -> &'static str {
    lock.get_or_init(|| {
        let sql = fetch_tpch_query_sql(number);
        Box::leak(sql.into_boxed_str())
    })
}

/// Which version of a TPC-H query, named by its benchmark suffix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// `_tt`: the query with no white-box string operation (a LIKE, a
    /// string ORDER BY key): strings are only compared by their hashes.
    Tt,
    /// `_tt_2`: the query with its white-box string operations, for the
    /// queries that have any ([`TT_2_QUERIES`]).
    Tt2,
    /// `_pgn`: the PoneglyphDB comparison, over the `_poneglyph` tables, for
    /// Q1, Q3, Q5, Q8, Q9 and Q18; any other query is its `_tt` variant.
    Pgn,
}

/// The queries with a `_tt_2` variant.
pub const TT_2_QUERIES: [u8; 8] = [1, 2, 4, 7, 9, 12, 14, 20];

/// The spec of TPC-H query `number` in `variant`.
pub fn query_spec(number: u8, variant: Variant) -> TpchQuerySpec {
    assert!(
        variant != Variant::Tt2 || TT_2_QUERIES.contains(&number),
        "TPC-H Q{number} has no _tt_2 variant"
    );
    let poneglyph = variant == Variant::Pgn;
    match number {
        1 => TpchQuerySpec {
            sql: match variant {
                Variant::Pgn => TPCH_Q1_PGN_SQL,
                Variant::Tt2 => cached_tpch_sql(&TPCH_Q1_TT_2_SQL, 1),
                Variant::Tt => TPCH_Q1_TT_SQL,
            },
            tables: if poneglyph {
                &["lineitem_poneglyph"]
            } else {
                &["lineitem"]
            },
        },
        2 => TpchQuerySpec {
            sql: match variant {
                Variant::Tt2 => TPCH_Q2_TT_2_SQL,
                Variant::Tt | Variant::Pgn => TPCH_Q2_TT_SQL,
            },
            tables: &["part", "supplier", "partsupp", "nation", "region"],
        },
        3 => TpchQuerySpec {
            sql: if poneglyph {
                TPCH_Q3_PGN_SQL
            } else {
                cached_tpch_sql(&TPCH_Q3_TT_SQL, 3)
            },
            tables: if poneglyph {
                &[
                    "customer_poneglyph",
                    "orders_poneglyph",
                    "lineitem_poneglyph",
                ]
            } else {
                &["customer", "orders", "lineitem"]
            },
        },
        4 => TpchQuerySpec {
            sql: match variant {
                Variant::Tt2 => TPCH_Q4_TT_2_SQL,
                Variant::Tt | Variant::Pgn => TPCH_Q4_TT_SQL,
            },
            tables: &["orders", "lineitem"],
        },
        5 => TpchQuerySpec {
            sql: if poneglyph {
                TPCH_Q5_PGN_SQL
            } else {
                cached_tpch_sql(&TPCH_Q5_TT_SQL, 5)
            },
            tables: if poneglyph {
                &[
                    "customer_poneglyph",
                    "orders_poneglyph",
                    "lineitem_poneglyph",
                    "nation_poneglyph",
                    "region_poneglyph",
                    "supplier_poneglyph",
                ]
            } else {
                &[
                    "customer", "orders", "lineitem", "nation", "region", "supplier",
                ]
            },
        },
        6 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q6_TT_SQL, 6),
            tables: &["lineitem"],
        },
        7 => TpchQuerySpec {
            sql: match variant {
                Variant::Tt2 => TPCH_Q7_TT_2_SQL,
                Variant::Tt | Variant::Pgn => TPCH_Q7_TT_SQL,
            },
            tables: &["customer", "orders", "lineitem", "nation", "supplier"],
        },
        8 => TpchQuerySpec {
            sql: if poneglyph {
                TPCH_Q8_PGN_SQL
            } else {
                TPCH_Q8_TT_SQL
            },
            tables: if poneglyph {
                &[
                    "customer_poneglyph",
                    "orders_poneglyph",
                    "lineitem_poneglyph",
                    "nation_poneglyph",
                    "region_poneglyph",
                    "part_poneglyph",
                    "supplier_poneglyph",
                ]
            } else {
                &[
                    "customer", "orders", "lineitem", "nation", "region", "part", "supplier",
                ]
            },
        },
        9 => TpchQuerySpec {
            sql: match variant {
                Variant::Pgn => TPCH_Q9_PGN_SQL,
                Variant::Tt2 => TPCH_Q9_TT_2_SQL,
                Variant::Tt => TPCH_Q9_TT_SQL,
            },
            tables: if poneglyph {
                &[
                    "nation_poneglyph",
                    "orders_poneglyph",
                    "lineitem_poneglyph",
                    "part_poneglyph",
                    "supplier_poneglyph",
                    "partsupp_poneglyph",
                ]
            } else {
                &[
                    "nation", "orders", "lineitem", "part", "supplier", "partsupp",
                ]
            },
        },
        10 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q10_TT_SQL, 10),
            tables: &["customer", "orders", "lineitem", "nation"],
        },
        11 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q11_TT_SQL, 11),
            tables: &["partsupp", "supplier", "nation"],
        },
        12 => TpchQuerySpec {
            sql: match variant {
                Variant::Tt2 => cached_tpch_sql(&TPCH_Q12_TT_2_SQL, 12),
                Variant::Tt | Variant::Pgn => TPCH_Q12_TT_SQL,
            },
            tables: &["orders", "lineitem"],
        },
        13 => TpchQuerySpec {
            sql: TPCH_Q13_TT_SQL,
            tables: &["customer", "orders"],
        },
        14 => TpchQuerySpec {
            sql: match variant {
                Variant::Tt2 => TPCH_Q14_TT_2_SQL,
                Variant::Tt | Variant::Pgn => TPCH_Q14_TT_SQL,
            },
            tables: &["lineitem", "part"],
        },
        15 => TpchQuerySpec {
            sql: TPCH_Q15_TT_SQL,
            tables: &["lineitem", "supplier"],
        },
        16 => TpchQuerySpec {
            sql: TPCH_Q16_TT_SQL,
            tables: &["part", "partsupp", "supplier"],
        },
        17 => TpchQuerySpec {
            sql: TPCH_Q17_TT_SQL,
            tables: &["part", "lineitem"],
        },
        18 => TpchQuerySpec {
            sql: if poneglyph {
                TPCH_Q18_PGN_SQL
            } else {
                cached_tpch_sql(&TPCH_Q18_TT_SQL, 18)
            },
            tables: if poneglyph {
                &[
                    "customer_poneglyph",
                    "orders_poneglyph",
                    "lineitem_poneglyph",
                ]
            } else {
                &["customer", "orders", "lineitem"]
            },
        },
        19 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q19_TT_SQL, 19),
            tables: &["part", "lineitem"],
        },
        20 => TpchQuerySpec {
            sql: match variant {
                Variant::Tt2 => TPCH_Q20_TT_2_SQL,
                Variant::Tt | Variant::Pgn => TPCH_Q20_TT_SQL,
            },
            tables: &["supplier", "nation", "partsupp", "lineitem", "part"],
        },
        21 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q21_TT_SQL, 21),
            tables: &["supplier", "nation", "lineitem", "orders"],
        },
        22 => TpchQuerySpec {
            sql: TPCH_Q22_TT_SQL,
            tables: &["customer", "orders"],
        },
        _ => panic!("unsupported TPC-H query number: {number}"),
    }
}

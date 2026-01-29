use std::{
    fs::{File, create_dir_all},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

use arithmetic::ACTIVATOR_COL_NAME;
use arrow::{
    array::{
        Array, ArrayRef, BooleanBuilder, Date32Array, Date64Array, Int32Builder, Int64Builder,
        RecordBatch, TimestampMicrosecondArray, TimestampMillisecondArray, TimestampNanosecondArray,
        TimestampSecondArray,
    },
    compute::concat as arrow_concat,
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
use tpchgen::generators::*;
use tpchgen_arrow::*;

const ROW_ID_COL_NAME: &str = "__row_id__";

#[derive(Clone)]
enum Expansion {
    Original(usize),
    Date32 { index: usize, name: String, nullable: bool },
    Date64 { index: usize, name: String, nullable: bool },
    Timestamp {
        index: usize,
        name: String,
        nullable: bool,
        unit: TimeUnit,
    },
}

fn build_expansions(schema: &Schema) -> (Vec<Expansion>, Vec<Field>) {
    let mut expansions = Vec::new();
    let mut fields = Vec::new();
    for (idx, field) in schema.fields().iter().enumerate() {
        match field.data_type() {
            DataType::Date32 => {
                let name = field.name().to_string();
                let nullable = field.is_nullable();
                expansions.push(Expansion::Original(idx));
                expansions.push(Expansion::Date32 { index: idx, name: name.clone(), nullable });
                fields.push((**field).clone());
                fields.push(Field::new(format!("{name}_year"), DataType::Int32, nullable));
                fields.push(Field::new(format!("{name}_month"), DataType::Int32, nullable));
                fields.push(Field::new(format!("{name}_day"), DataType::Int32, nullable));
            }
            DataType::Date64 => {
                let name = field.name().to_string();
                let nullable = field.is_nullable();
                expansions.push(Expansion::Original(idx));
                expansions.push(Expansion::Date64 { index: idx, name: name.clone(), nullable });
                fields.push((**field).clone());
                fields.push(Field::new(format!("{name}_year"), DataType::Int32, nullable));
                fields.push(Field::new(format!("{name}_month"), DataType::Int32, nullable));
                fields.push(Field::new(format!("{name}_day"), DataType::Int32, nullable));
                fields.push(Field::new(format!("{name}_time"), DataType::Int32, nullable));
            }
            DataType::Timestamp(unit, _) => {
                let name = field.name().to_string();
                let nullable = field.is_nullable();
                expansions.push(Expansion::Original(idx));
                expansions.push(Expansion::Timestamp {
                    index: idx,
                    name: name.clone(),
                    nullable,
                    unit: unit.clone(),
                });
                fields.push((**field).clone());
                fields.push(Field::new(format!("{name}_year"), DataType::Int32, nullable));
                fields.push(Field::new(format!("{name}_month"), DataType::Int32, nullable));
                fields.push(Field::new(format!("{name}_day"), DataType::Int32, nullable));
                fields.push(Field::new(format!("{name}_time"), DataType::Int32, nullable));
            }
            _ => {
                expansions.push(Expansion::Original(idx));
                fields.push((**field).clone());
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
                    let dt = date32_to_datetime(array.value(i))
                        .expect("date32 conversion");
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
                    let dt =
                        as_datetime::<Date64Type>(array.value(i)).expect("date64 conversion");
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

/// Check if n is a power of two
fn is_power_of_two(n: usize) -> bool {
    n != 0 && (n & (n - 1)) == 0
}

/// Return the next power of two >= n
fn next_power_of_two(n: usize) -> usize {
    if n <= 1 {
        n.max(1)
    } else {
        n.next_power_of_two()
    }
}

/// Write Parquet after augmenting with a stable `row_id` column and an
/// `__activator__` Boolean column, then pad by duplicating the last row until the
/// total row count is a power of two (appended rows have __activator__=false).
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

    // Build output schema = expanded fields + row_id: Int64 + __activator__: Boolean
    let mut fields: Vec<Field> = expanded_schema.fields().iter().map(|f| (**f).clone()).collect();
    fields.push(Field::new(ROW_ID_COL_NAME, DataType::Int64, false));
    fields.push(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false));
    let out_schema = Arc::new(Schema::new(fields));

    let file = File::create(path_ref).expect("create parquet file");
    let mut writer = ArrowWriter::try_new(file, Arc::clone(&out_schema), None).expect("new writer");

    let mut total_rows: usize = 0;
    let mut next_row_id: i64 = 0;
    let mut last_nonempty_batch: Option<RecordBatch> = None;

    // Stream original batches, tagging __activator__=true and writing out directly
    for batch in batches {
        let n = batch.num_rows();
        if n == 0 {
            continue;
        }
        let batch = expand_batch(&batch, &expansions, &expanded_schema);
        total_rows += n;
        last_nonempty_batch = Some(batch.clone());

        // row_id increments across batches to preserve a stable order
        let mut row_id_builder = Int64Builder::new();
        for offset in 0..n {
            row_id_builder.append_value(next_row_id + offset as i64);
        }
        next_row_id += n as i64;
        let row_id = Arc::new(row_id_builder.finish());

        // __activator__=true for existing rows
        let mut act_builder = BooleanBuilder::new();
        for _ in 0..n {
            act_builder.append_value(true);
        }
        let activator = Arc::new(act_builder.finish());

        // Rebuild the batch with the new schema + extra __activator__ column
        let mut cols = batch.columns().to_vec();
        cols.push(row_id);
        cols.push(activator);
        let out_batch = RecordBatch::try_new(Arc::clone(&out_schema), cols)
            .expect("rebuild batch with activator");
        writer.write(&out_batch).expect("write batch");
    }

    // If there were no rows, just close the writer.
    if total_rows == 0 {
        writer.close().expect("close writer");
        return;
    }

    // Determine padding needed to reach power of two
    if !is_power_of_two(total_rows) {
        let target = next_power_of_two(total_rows);
        let pad = target - total_rows;
        let last_batch = last_nonempty_batch.expect("must have last batch");
        let last_idx = last_batch.num_rows() - 1;

        // Build per-column arrays by repeating the last row value `pad` times
        let mut pad_cols = Vec::with_capacity(last_batch.num_columns() + 2);
        for col in last_batch.columns() {
            let one = col.slice(last_idx, 1);
            // Create a slice of &dyn Array repeated `pad` times
            let repeated: Vec<&dyn arrow::array::Array> =
                std::iter::repeat_n(one.as_ref(), pad).collect();
            let repeated_arr = arrow_concat(&repeated).expect("concat repeated scalars");
            pad_cols.push(repeated_arr);
        }

        let mut row_id_builder = Int64Builder::new();
        for offset in 0..pad {
            row_id_builder.append_value(next_row_id + offset as i64);
        }
        let pad_row_id = Arc::new(row_id_builder.finish());
        pad_cols.push(pad_row_id);

        // __activator__=false for appended rows
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

/// Write Parquet with the original schema and rows (no row_id/activator, no padding).
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

/// Generate TPC-H Parquet files at the given scale factor in the specified
/// output directory (if it doesn't exist, it will be created).
// Note that the tables are further preprocessed as follows:
// - All tables have an additional __row_id__ Int64 column with stable row
//   indices, plus the boolean __activator__ column set true for existing rows
// - The tables are padded by duplicating the last row until the total row count
//   is a power of two; the appended rows have __activator__=false
pub fn generate_parquet_scale<P: AsRef<Path>>(scale: f64, out_dir: P) {
    let out = out_dir.as_ref();

    // Each generator uses (scale, part, step) with part=1, step=1 for
    // single-threaded Adjust batch sizes as needed

    // nation
    {
        let generator = NationGenerator::new(scale, 1, 1);
        let mut it = NationArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        let generator_raw = NationGenerator::new(scale, 1, 1);
        let mut it_raw = NationArrow::new(generator_raw).with_batch_size(DEFAULT_BATCH_SIZE);
        let orig_out = out.with_file_name(format!(
            "orig-{}",
            out.file_name().unwrap_or_default().to_string_lossy()
        ));
        write_parquet_raw(orig_out.join("nation.parquet"), &schema, &mut it_raw);
        write_parquet(out.join("nation.parquet"), &schema, &mut it);
    }
    // region
    {
        let generator = RegionGenerator::new(scale, 1, 1);
        let mut it = RegionArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        let generator_raw = RegionGenerator::new(scale, 1, 1);
        let mut it_raw = RegionArrow::new(generator_raw).with_batch_size(DEFAULT_BATCH_SIZE);
        let orig_out = out.with_file_name(format!(
            "orig-{}",
            out.file_name().unwrap_or_default().to_string_lossy()
        ));
        write_parquet_raw(orig_out.join("region.parquet"), &schema, &mut it_raw);
        write_parquet(out.join("region.parquet"), &schema, &mut it);
    }
    // part
    {
        let generator = PartGenerator::new(scale, 1, 1);
        let mut it = PartArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        let generator_raw = PartGenerator::new(scale, 1, 1);
        let mut it_raw = PartArrow::new(generator_raw).with_batch_size(DEFAULT_BATCH_SIZE);
        let orig_out = out.with_file_name(format!(
            "orig-{}",
            out.file_name().unwrap_or_default().to_string_lossy()
        ));
        write_parquet_raw(orig_out.join("part.parquet"), &schema, &mut it_raw);
        write_parquet(out.join("part.parquet"), &schema, &mut it);
    }
    // supplier
    {
        let generator = SupplierGenerator::new(scale, 1, 1);
        let mut it = SupplierArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        let generator_raw = SupplierGenerator::new(scale, 1, 1);
        let mut it_raw = SupplierArrow::new(generator_raw).with_batch_size(DEFAULT_BATCH_SIZE);
        let orig_out = out.with_file_name(format!(
            "orig-{}",
            out.file_name().unwrap_or_default().to_string_lossy()
        ));
        write_parquet_raw(orig_out.join("supplier.parquet"), &schema, &mut it_raw);
        write_parquet(out.join("supplier.parquet"), &schema, &mut it);
    }
    // partsupp
    {
        let generator = PartSuppGenerator::new(scale, 1, 1);
        let mut it = PartSuppArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        let generator_raw = PartSuppGenerator::new(scale, 1, 1);
        let mut it_raw = PartSuppArrow::new(generator_raw).with_batch_size(DEFAULT_BATCH_SIZE);
        let orig_out = out.with_file_name(format!(
            "orig-{}",
            out.file_name().unwrap_or_default().to_string_lossy()
        ));
        write_parquet_raw(orig_out.join("partsupp.parquet"), &schema, &mut it_raw);
        write_parquet(out.join("partsupp.parquet"), &schema, &mut it);
    }
    // customer
    {
        let generator = CustomerGenerator::new(scale, 1, 1);
        let mut it = CustomerArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        let generator_raw = CustomerGenerator::new(scale, 1, 1);
        let mut it_raw = CustomerArrow::new(generator_raw).with_batch_size(DEFAULT_BATCH_SIZE);
        let orig_out = out.with_file_name(format!(
            "orig-{}",
            out.file_name().unwrap_or_default().to_string_lossy()
        ));
        write_parquet_raw(orig_out.join("customer.parquet"), &schema, &mut it_raw);
        write_parquet(out.join("customer.parquet"), &schema, &mut it);
    }
    // orders
    {
        let generator = OrderGenerator::new(scale, 1, 1);
        let mut it = OrderArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        let generator_raw = OrderGenerator::new(scale, 1, 1);
        let mut it_raw = OrderArrow::new(generator_raw).with_batch_size(DEFAULT_BATCH_SIZE);
        let orig_out = out.with_file_name(format!(
            "orig-{}",
            out.file_name().unwrap_or_default().to_string_lossy()
        ));
        write_parquet_raw(orig_out.join("orders.parquet"), &schema, &mut it_raw);
        write_parquet(out.join("orders.parquet"), &schema, &mut it);
    }
    // lineitem
    {
        let generator = LineItemGenerator::new(scale, 1, 1);
        let mut it = LineItemArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        let generator_raw = LineItemGenerator::new(scale, 1, 1);
        let mut it_raw = LineItemArrow::new(generator_raw).with_batch_size(DEFAULT_BATCH_SIZE);
        let orig_out = out.with_file_name(format!(
            "orig-{}",
            out.file_name().unwrap_or_default().to_string_lossy()
        ));
        write_parquet_raw(orig_out.join("lineitem.parquet"), &schema, &mut it_raw);
        write_parquet(out.join("lineitem.parquet"), &schema, &mut it);
    }
}

/// Preprocess an existing Parquet file using the same logic as `generate_parquet_scale`.
/// This expands date/time columns, adds `__row_id__` and `__activator__`, and pads to
/// a power-of-two row count by duplicating the last row.
pub fn preprocess_parquet<P: AsRef<Path>>(input: P, output: P) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(input.as_ref())?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let schema = Arc::clone(builder.schema());
    let reader = builder.build()?;
    write_parquet(output, &schema, reader.into_iter().map(|batch| batch.expect("read batch")));
    Ok(())
}

/// Absolute path helper to a Parquet file under this crate's `test-data` dir.
/// Example: `test_data_path("lineitem.parquet")`
pub fn test_data_path(file: impl AsRef<Path>) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test-data")
        .join(file)
}

/// Absolute path helper to a Parquet file under this crate's `bench-data` dir.
/// Example: `bench_data_path("orders.parquet")`
pub fn bench_data_path(file: impl AsRef<Path>) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("bench-data")
        .join(file)
}

/// Description of a TPC-H query including the SQL text and required tables.
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
        // DataFusion does not plan EXTRACT(YEAR FROM ...) yet; rewrite to date_part.
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

static TPCH_Q1_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q2_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q3_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q4_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q5_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q6_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q7_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q8_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q9_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q10_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q11_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q12_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q13_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q14_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q15_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q16_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q17_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q18_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q19_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q20_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q21_SQL: OnceLock<&'static str> = OnceLock::new();
static TPCH_Q22_SQL: OnceLock<&'static str> = OnceLock::new();

fn cached_tpch_sql(lock: &'static OnceLock<&'static str>, number: u8) -> &'static str {
    lock.get_or_init(|| {
        let sql = fetch_tpch_query_sql(number);
        Box::leak(sql.into_boxed_str())
    })
}

/// Return the [`TpchQuerySpec`] for the provided query number. Query SQL is
/// loaded from DuckDB's TPCH extension on first use to avoid hardcoding.
pub fn query_spec(number: u8) -> TpchQuerySpec {
    match number {
        1 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q1_SQL, 1),
            tables: &["lineitem"],
        },
        2 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q2_SQL, 2),
            tables: &["part", "supplier", "partsupp", "nation", "region"],
        },
        3 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q3_SQL, 3),
            tables: &["customer", "orders", "lineitem"],
        },
        4 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q4_SQL, 4),
            tables: &["orders", "lineitem"],
        },
        5 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q5_SQL, 5),
            tables: &[
                "customer", "orders", "lineitem", "nation", "region", "supplier",
            ],
        },
        6 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q6_SQL, 6),
            tables: &["lineitem"],
        },
        7 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q7_SQL, 7),
            tables: &["customer", "orders", "lineitem", "nation", "supplier"],
        },
        8 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q8_SQL, 8),
            tables: &[
                "customer", "orders", "lineitem", "nation", "region", "part", "supplier",
            ],
        },
        9 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q9_SQL, 9),
            tables: &[
                "nation", "orders", "lineitem", "part", "supplier", "partsupp",
            ],
        },
        10 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q10_SQL, 10),
            tables: &["customer", "orders", "lineitem", "nation"],
        },
        11 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q11_SQL, 11),
            tables: &["partsupp", "supplier", "nation"],
        },
        12 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q12_SQL, 12),
            tables: &["orders", "lineitem"],
        },
        13 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q13_SQL, 13),
            tables: &["customer", "orders"],
        },
        14 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q14_SQL, 14),
            tables: &["lineitem", "part"],
        },
        15 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q15_SQL, 15),
            tables: &["lineitem", "supplier"],
        },
        16 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q16_SQL, 16),
            tables: &["part", "partsupp"],
        },
        17 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q17_SQL, 17),
            tables: &["part", "lineitem"],
        },
        18 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q18_SQL, 18),
            tables: &["customer", "orders", "lineitem"],
        },
        19 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q19_SQL, 19),
            tables: &["part", "lineitem"],
        },
        20 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q20_SQL, 20),
            tables: &["supplier", "nation", "partsupp", "lineitem"],
        },
        21 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q21_SQL, 21),
            tables: &["supplier", "nation", "lineitem", "orders"],
        },
        22 => TpchQuerySpec {
            sql: cached_tpch_sql(&TPCH_Q22_SQL, 22),
            tables: &["customer", "orders"],
        },
        _ => panic!("unsupported TPC-H query number: {number}"),
    }
}

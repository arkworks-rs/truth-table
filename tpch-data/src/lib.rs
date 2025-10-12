use std::{
    fs::{File, create_dir_all},
    path::{Path, PathBuf},
    sync::Arc,
};

use arrow::{
    array::{BooleanBuilder, RecordBatch},
    compute::concat as arrow_concat,
    datatypes::{DataType, Field, Schema},
};
use parquet::arrow::arrow_writer::ArrowWriter;
use tpchgen::generators::*;
use tpchgen_arrow::*;

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

/// Write Parquet after augmenting with an `activator` Boolean column and
/// padding rows by duplicating the last row until the total row count is a
/// power of two (appended rows have activator=false).
fn write_parquet<P: AsRef<Path>>(
    path: P,
    orig_schema: &arrow::datatypes::SchemaRef,
    batches: impl Iterator<Item = RecordBatch>,
) {
    let path_ref = path.as_ref();
    if let Some(parent) = path_ref.parent() {
        create_dir_all(parent).expect("create output dir");
    }

    // Build output schema = original fields + activator: Boolean
    let mut fields: Vec<Field> = orig_schema.fields().iter().map(|f| (**f).clone()).collect();
    fields.push(Field::new("activator", DataType::Boolean, false));
    let out_schema = Arc::new(Schema::new(fields));

    let file = File::create(path_ref).expect("create parquet file");
    let mut writer = ArrowWriter::try_new(file, Arc::clone(&out_schema), None).expect("new writer");

    let mut total_rows: usize = 0;
    let mut last_nonempty_batch: Option<RecordBatch> = None;

    // Stream original batches, tagging activator=true and writing out directly
    for batch in batches {
        let n = batch.num_rows();
        if n == 0 {
            continue;
        }
        total_rows += n;
        last_nonempty_batch = Some(batch.clone());

        // activator=true for existing rows
        let mut act_builder = BooleanBuilder::new();
        for _ in 0..n {
            act_builder.append_value(true);
        }
        let activator = Arc::new(act_builder.finish());

        // Rebuild the batch with the new schema + extra activator column
        let mut cols = batch.columns().to_vec();
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
        let mut pad_cols = Vec::with_capacity(last_batch.num_columns() + 1);
        for col in last_batch.columns() {
            let one = col.slice(last_idx, 1);
            // Create a slice of &dyn Array repeated `pad` times
            let repeated: Vec<&dyn arrow::array::Array> =
                std::iter::repeat_n(one.as_ref(), pad).collect();
            let repeated_arr = arrow_concat(&repeated).expect("concat repeated scalars");
            pad_cols.push(repeated_arr);
        }

        // activator=false for appended rows
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

/// Generate TPC-H Parquet files at the given scale factor in the specified
/// output directory (if it doesn't exist, it will be created).
// Note that the tables are further preprocessed as follows:
// - All tables have an additional boolean ACTIVATOR_COL_NAME column, which is
//   set true for the existing rows
// - The tables are padded by duplicating the last row until the total row count
//   is a power of two; the appended rows have activator=false
pub fn generate_parquet_scale<P: AsRef<Path>>(scale: f64, out_dir: P) {
    let out = out_dir.as_ref();

    // Each generator uses (scale, part, step) with part=1, step=1 for
    // single-threaded Adjust batch sizes as needed

    // nation
    {
        let generator = NationGenerator::new(scale, 1, 1);
        let mut it = NationArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        write_parquet(out.join("nation.parquet"), &schema, &mut it);
    }
    // region
    {
        let generator = RegionGenerator::new(scale, 1, 1);
        let mut it = RegionArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        write_parquet(out.join("region.parquet"), &schema, &mut it);
    }
    // part
    {
        let generator = PartGenerator::new(scale, 1, 1);
        let mut it = PartArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        write_parquet(out.join("part.parquet"), &schema, &mut it);
    }
    // supplier
    {
        let generator = SupplierGenerator::new(scale, 1, 1);
        let mut it = SupplierArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        write_parquet(out.join("supplier.parquet"), &schema, &mut it);
    }
    // partsupp
    {
        let generator = PartSuppGenerator::new(scale, 1, 1);
        let mut it = PartSuppArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        write_parquet(out.join("partsupp.parquet"), &schema, &mut it);
    }
    // customer
    {
        let generator = CustomerGenerator::new(scale, 1, 1);
        let mut it = CustomerArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        write_parquet(out.join("customer.parquet"), &schema, &mut it);
    }
    // orders
    {
        let generator = OrderGenerator::new(scale, 1, 1);
        let mut it = OrderArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        write_parquet(out.join("orders.parquet"), &schema, &mut it);
    }
    // lineitem
    {
        let generator = LineItemGenerator::new(scale, 1, 1);
        let mut it = LineItemArrow::new(generator).with_batch_size(DEFAULT_BATCH_SIZE);
        let schema = Arc::clone(it.schema());
        write_parquet(out.join("lineitem.parquet"), &schema, &mut it);
    }
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

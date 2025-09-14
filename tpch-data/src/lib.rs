use std::fs::{create_dir_all, File};
use std::path::Path;
use std::sync::Arc;

use arrow::array::RecordBatch;
use parquet::arrow::arrow_writer::ArrowWriter;
use tpchgen::generators::*;
use tpchgen_arrow::*;

fn write_parquet<P: AsRef<Path>>(path: P, schema: &arrow::datatypes::SchemaRef, batches: impl Iterator<Item = RecordBatch>) {
    let path_ref = path.as_ref();
    if let Some(parent) = path_ref.parent() {
        create_dir_all(parent).expect("create output dir");
    }
    let file = File::create(path_ref).expect("create parquet file");
    let mut writer = ArrowWriter::try_new(file, Arc::clone(schema), None).expect("new writer");
    for batch in batches {
        writer.write(&batch).expect("write batch");
    }
    writer.close().expect("close writer");
}

pub fn generate_parquet_scale<P: AsRef<Path>>(scale: f64, out_dir: P) {
    let out = out_dir.as_ref();

    // Each generator uses (scale, part, step) with part=1, step=1 for single-threaded
    // Adjust batch sizes as needed

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


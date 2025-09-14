use std::path::PathBuf;

fn main() {
    // Generate small test data at scale 0.01 into tpch-data/test-data
    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-data");
    tpch_data::generate_parquet_scale(0.01, out_dir);
}

use std::path::PathBuf;
// Generate small test data at scale 0.01 into tpch-data/test-data
// Note that the tables are further preprocessed as follows:
// - All tables have an additional boolean "activator" column, which is set true
//   for the existing rows
// - The tables are padded by duplicating the last row until the total row count
//   is a power of two; the appended rows have activator=false
fn main() {
    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-data");
    tpch_data::generate_parquet_scale(0.01, out_dir);
}

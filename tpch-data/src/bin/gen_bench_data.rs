use std::{env, path::PathBuf};
// Usage: gen_bench_data <scale>
// Note that the tables are further preprocessed as follows:
// - All tables have an additional boolean "activator" column, which is set true
//   for the existing rows
// - The tables are padded by duplicating the last row until the total row count
//   is a power of two; the appended rows have activator=false
fn main() {
    let scale: f64 = env::args()
        .nth(1)
        .expect("Usage: gen_bench_data <scale>")
        .parse()
        .expect("scale must be a floating point number");

    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bench-data");
    tpch_data::generate_parquet_scale(scale, out);
}

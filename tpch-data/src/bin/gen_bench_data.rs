use std::env;
use std::path::PathBuf;

fn main() {
    // Usage: gen_bench_data <scale>
    let scale: f64 = env::args()
        .nth(1)
        .expect("Usage: gen_bench_data <scale>")
        .parse()
        .expect("scale must be a floating point number");

    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bench-data");
    tpch_data::generate_parquet_scale(scale, out);
}

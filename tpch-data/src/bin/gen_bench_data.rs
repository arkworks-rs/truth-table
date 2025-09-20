use clap::Parser;
use std::path::PathBuf;
// Usage: gen_bench_data <scale> [--out-dir DIR]
// Note that the tables are further preprocessed as follows:
// - All tables have an additional boolean "activator" column, which is set true
//   for the existing rows
// - The tables are padded by duplicating the last row until the total row count
//   is a power of two; the appended rows have activator=false

#[derive(Parser, Debug)]
#[command(
    name = "gen_bench_data",
    about = "Generate TPC-H Parquet for benchmarking"
)]
struct Cli {
    /// Scale factor (e.g., 1.0 for SF1)
    scale: f64,

    /// Output directory (defaults to tpch-data/bench-data)
    #[arg(long)]
    out_dir: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();
    let out = cli
        .out_dir
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bench-data"));
    tpch_data::generate_parquet_scale(cli.scale, out);
}

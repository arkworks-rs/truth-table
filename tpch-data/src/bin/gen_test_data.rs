use clap::Parser;
use std::path::PathBuf;
// Generate small test data at scale 0.01 into tpch-data/test-data
// Note that the tables are further preprocessed as follows:
// - All tables have an additional boolean "activator" column, which is set true
//   for the existing rows
// - The tables are padded by duplicating the last row until the total row count
//   is a power of two; the appended rows have activator=false
#[derive(Parser, Debug)]
#[command(
    name = "gen_test_data",
    about = "Generate small TPC-H Parquet for testing"
)]
struct Cli {
    /// Scale factor (default 0.01)
    #[arg(long, default_value_t = 0.01)]
    scale: f64,

    /// Output directory (defaults to tpch-data/test-data)
    #[arg(long)]
    out_dir: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();
    let out_dir = cli
        .out_dir
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-data"));
    tpch_data::generate_parquet_scale(cli.scale, out_dir);
}

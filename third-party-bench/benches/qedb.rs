use std::path::Path;

use qedb::bench::benchmark_parquet_once;
use tpch_data::preprocess_parquet;

// Paths for input/output artifacts.
const PARQUET_DIR: &str = "artifact";
const PARQUET_SUBDIR_PREFIX: &str = "size_";
const QUERY_DIR: &str = "Filter";
const PARQUET_FILE_PREFIX: &str = "bench_table_";

// Table sizes as powers of two.
const TABLE_POW_MIN: u32 = 10;
const TABLE_POW_MAX: u32 = 20;

// Query string (SQL). `{table}` will be replaced with the parquet file stem.
const QUERY_SQL_TEMPLATE: &str = "SELECT a FROM {table} WHERE b=4379";

fn parquet_paths(bench_root: &Path, pow: u32) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = bench_root
        .join(PARQUET_DIR)
        .join(format!("{PARQUET_SUBDIR_PREFIX}{pow}"));
    let query_dir = dir.join(QUERY_DIR);
    let parquet = query_dir.join(format!("{PARQUET_FILE_PREFIX}{pow}.parquet"));
    let preprocessed = query_dir.join(format!("{PARQUET_FILE_PREFIX}{pow}_preprocessed.parquet"));
    (parquet, preprocessed)
}

fn main() {
    let bench_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    println!("table_sizes: 2^{}..=2^{}", TABLE_POW_MIN, TABLE_POW_MAX);

    for pow in TABLE_POW_MIN..=TABLE_POW_MAX {
        let (parquet_path, preprocessed_path) = parquet_paths(bench_root, pow);

        if !parquet_path.exists() {
            panic!(
                "missing parquet at {}. Generate it first.",
                parquet_path.display()
            );
        }

        if !preprocessed_path.exists() {
            std::fs::create_dir_all(preprocessed_path.parent().unwrap())
                .expect("create preprocessed dir");
            preprocess_parquet(&parquet_path, &preprocessed_path).expect("preprocess parquet");
        }

        let table_name = preprocessed_path
            .file_stem()
            .and_then(|name| name.to_str())
            .expect("parquet path must have a file stem");
        let query_sql = QUERY_SQL_TEMPLATE.replace("{table}", table_name);

        println!("pow: {pow} parquet: {}", preprocessed_path.display());
        let output =
            benchmark_parquet_once(preprocessed_path.to_string_lossy().as_ref(), &query_sql)
                .expect("qedb bench");

        println!("prove_ms: {}", output.prove_ms);
        println!("verify_ms: {}", output.verify_ms);
        println!("proof_bytes: {}", output.proof_bytes);
        println!("----------------------------------------");
    }
}

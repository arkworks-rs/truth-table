use std::{path::Path, time::Instant};

use exec::{commit::CommitBuilder, prove::ProveBuilder, setup::SetupBuilder, verify::VerifyBuilder};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use tpch_data::preprocess_parquet;

// Paths for input/output artifacts.
const PARQUET_DIR: &str = "artifact";
const PARQUET_SUBDIR_PREFIX: &str = "size_";
const QUERY_DIR: &str = "Filter";
const PARQUET_FILE_PREFIX: &str = "bench_table_";
const ORACLE_DIR: &str = "artifact";
const PROOF_PATH: &str = "artifact/bench.proof";
const PK_FILENAME_PREFIX: &str = "tt_pk_";
const VK_FILENAME_PREFIX: &str = "tt_vk_";

// Table sizes as powers of two.
const TABLE_POW_MIN: u32 = 10;
const TABLE_POW_MAX: u32 = 20;

// Query string (SQL). `{table}` will be replaced with the parquet file stem.
const QUERY_SQL_TEMPLATE: &str = "SELECT a FROM {table} WHERE b=4379";

fn ensure_dir(path: &Path) {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)
        .unwrap_or_else(|err| panic!("failed to create directory {}: {err}", dir.display()));
}

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
        let oracle_path = bench_root
            .join(ORACLE_DIR)
            .join(format!("{PARQUET_SUBDIR_PREFIX}{pow}"))
            .join(QUERY_DIR)
            .join(format!("{PARQUET_FILE_PREFIX}{pow}.oracle"));
        let proof_path = bench_root.join(PROOF_PATH);

        if !parquet_path.exists() {
            panic!(
                "missing parquet at {}. Generate it first.",
                parquet_path.display()
            );
        }

        let raw_file = std::fs::File::open(&parquet_path).unwrap_or_else(|err| {
            panic!("failed to open parquet {}: {err}", parquet_path.display())
        });
        let builder = ParquetRecordBatchReaderBuilder::try_new(raw_file).expect("parquet reader");
        let total_rows = builder.metadata().file_metadata().num_rows() as usize;
        let log_size = (total_rows.max(1) as f64).log2().ceil() as usize;
        let pk_path = bench_root
            .join(PARQUET_DIR)
            .join(format!("{PARQUET_SUBDIR_PREFIX}{pow}"))
            .join(format!("{PK_FILENAME_PREFIX}{log_size}.pk"));
        let vk_path = bench_root
            .join(PARQUET_DIR)
            .join(format!("{PARQUET_SUBDIR_PREFIX}{pow}"))
            .join(format!("{VK_FILENAME_PREFIX}{log_size}.vk"));
        println!("pow: {pow} parquet_rows: {total_rows} log_size: {log_size}");

        if !pk_path.exists() || !vk_path.exists() {
            ensure_dir(&pk_path);
            ensure_dir(&vk_path);
            let start = Instant::now();
            let runner = SetupBuilder::new()
                .with_size_label(Some(log_size.to_string()))
                .with_pk_path(Some(pk_path.clone()))
                .with_vk_path(Some(vk_path.clone()))
                .build()
                .expect("build setup");
            runner.run().expect("tt setup");
            println!("setup_ms: {}", start.elapsed().as_millis());
        }

        if !preprocessed_path.exists() {
            ensure_dir(&preprocessed_path);
            let start = Instant::now();
            preprocess_parquet(&parquet_path, &preprocessed_path).expect("preprocess parquet");
            println!("preprocess_ms: {}", start.elapsed().as_millis());
        }

        if !oracle_path.exists() {
            ensure_dir(&oracle_path);
            let start = Instant::now();
            let runner = CommitBuilder::new()
                .with_parquet_path(preprocessed_path.clone())
                .with_pk_path(pk_path.clone())
                .with_output_path(Some(oracle_path.clone()))
                .build()
                .expect("build commit");
            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            rt.block_on(runner.run()).expect("tt commit");
            println!("commit_ms: {}", start.elapsed().as_millis());
        }

        let table_name = preprocessed_path
            .file_stem()
            .and_then(|name| name.to_str())
            .expect("parquet path must have a file stem");
        let query_sql = QUERY_SQL_TEMPLATE.replace("{table}", table_name);

        let start = Instant::now();
        let runner = ProveBuilder::new()
            .with_query(query_sql.clone())
            .with_parquet_paths(vec![preprocessed_path.clone()])
            .with_oracle_paths(vec![oracle_path.clone()])
            .with_pk_path(pk_path.clone())
            .with_output_path(Some(proof_path.clone()))
            .build()
            .expect("build prove");
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(runner.run()).expect("tt prove");
        let prove_ms = start.elapsed().as_millis();
        let proof_size = std::fs::metadata(&proof_path)
            .map(|meta| meta.len())
            .unwrap_or(0);
        println!("prove_ms: {}", prove_ms);
        println!("proof_bytes: {}", proof_size);

        let start = Instant::now();
        let runner = VerifyBuilder::new()
            .with_query(query_sql)
            .with_parquet_paths(vec![preprocessed_path.clone()])
            .with_oracle_paths(vec![oracle_path.clone()])
            .with_proof_path(proof_path.clone())
            .with_vk_path(vk_path.clone())
            .build()
            .expect("build verify");
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(runner.run()).expect("tt verify");
        println!("verify_ms: {}", start.elapsed().as_millis());
    }
}

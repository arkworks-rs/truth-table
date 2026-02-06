use std::{path::Path, time::Instant};

use exec::{
    commit::CommitBuilder, prove::ProveBuilder, setup::SetupBuilder, verify::VerifyBuilder,
};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use tpch_data::preprocess_parquet;

// Paths for input/output artifacts.
const PARQUET_DIR: &str = "artifact";
const PARQUET_SUBDIR_PREFIX: &str = "size_";
const PARQUET_FILE_PREFIX: &str = "bench_table_";
const JOIN_TABLE_PREFIX_A: &str = "bench_table";
const JOIN_TABLE_PREFIX_B: &str = "bench_table_2";
const ORACLE_DIR: &str = "artifact";
const PROOF_FILENAME: &str = "bench.proof";
const PK_FILENAME_PREFIX: &str = "tt_pk_";
const VK_FILENAME_PREFIX: &str = "tt_vk_";

// Table sizes as powers of two.
const TABLE_POW_MIN: u32 = 10;
const TABLE_POW_MAX: u32 = 20;

struct QuerySpec {
    name: &'static str,
    dir: &'static str,
    sql: &'static str,
}

// Query strings (SQL). `{table}` will be replaced with the parquet file stem.
const QUERIES: &[QuerySpec] = &[
    QuerySpec {
        name: "filter",
        dir: "Filter",
        sql: "SELECT a FROM {table} WHERE b=4379",
    },
    QuerySpec {
        name: "filter_complex_and",
        dir: "filter_complex_and",
        sql: "SELECT * FROM {table} WHERE a = 1 AND b = 2 AND c = 3 AND d = 4",
    },
    QuerySpec {
        name: "filter_complex_or",
        dir: "filter_complex_or",
        sql: "SELECT * FROM {table} WHERE a = 1 OR b = 2 OR c = 3 OR d = 4",
    },
    QuerySpec {
        name: "aggregate_count",
        dir: "aggregate_count",
        sql: "SELECT COUNT(*) FROM {table}",
    },
    QuerySpec {
        name: "aggregate_sum",
        dir: "aggregate_sum",
        sql: "SELECT a, SUM(b) FROM {table} GROUP BY a",
    },
    QuerySpec {
        name: "join",
        dir: "Join",
        sql: "SELECT {table1}.a, {table2}.a FROM {table1} JOIN {table2} ON {table1}.a = {table2}.a",
    },
];

fn ensure_dir(path: &Path) {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)
        .unwrap_or_else(|err| panic!("failed to create directory {}: {err}", dir.display()));
}

fn parquet_paths(
    bench_root: &Path,
    pow: u32,
    query_dir: &str,
    table_prefix: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = bench_root
        .join(PARQUET_DIR)
        .join(format!("{PARQUET_SUBDIR_PREFIX}{pow}"));
    let query_dir = dir.join(query_dir);
    let parquet = query_dir.join(format!("{table_prefix}_{pow}.parquet"));
    let preprocessed = query_dir.join(format!("{table_prefix}_{pow}_preprocessed.parquet"));
    (parquet, preprocessed)
}

fn main() {
    let bench_root = Path::new(env!("CARGO_MANIFEST_DIR"));

    println!("table_sizes: 2^{}..=2^{}", TABLE_POW_MIN, TABLE_POW_MAX);

    for pow in TABLE_POW_MIN..=TABLE_POW_MAX {
        for query in QUERIES {
            let is_join = query.name == "join";
            let (parquet_path, preprocessed_path) =
                parquet_paths(bench_root, pow, query.dir, JOIN_TABLE_PREFIX_A);
            let (parquet_path_b, preprocessed_path_b) = if is_join {
                parquet_paths(bench_root, pow, query.dir, JOIN_TABLE_PREFIX_B)
            } else {
                (std::path::PathBuf::new(), std::path::PathBuf::new())
            };
            let oracle_path = bench_root
                .join(ORACLE_DIR)
                .join(format!("{PARQUET_SUBDIR_PREFIX}{pow}"))
                .join(query.dir)
                .join(format!("{JOIN_TABLE_PREFIX_A}_{pow}.oracle"));
            let oracle_path_b = if is_join {
                bench_root
                    .join(ORACLE_DIR)
                    .join(format!("{PARQUET_SUBDIR_PREFIX}{pow}"))
                    .join(query.dir)
                    .join(format!("{JOIN_TABLE_PREFIX_B}_{pow}.oracle"))
            } else {
                std::path::PathBuf::new()
            };
            let proof_path = bench_root
                .join(ORACLE_DIR)
                .join(format!("{PARQUET_SUBDIR_PREFIX}{pow}"))
                .join(query.dir)
                .join(PROOF_FILENAME);

            if !parquet_path.exists() {
                panic!(
                    "missing parquet at {}. Generate it first.",
                    parquet_path.display()
                );
            }
            if is_join && !parquet_path_b.exists() {
                panic!(
                    "missing parquet at {}. Generate it first.",
                    parquet_path_b.display()
                );
            }

            let raw_file = std::fs::File::open(&parquet_path).unwrap_or_else(|err| {
                panic!("failed to open parquet {}: {err}", parquet_path.display())
            });
            let builder =
                ParquetRecordBatchReaderBuilder::try_new(raw_file).expect("parquet reader");
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

            println!(
                "pow: {pow} query: {} parquet_rows: {total_rows} log_size: {log_size}",
                query.name
            );

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
            if is_join && !preprocessed_path_b.exists() {
                ensure_dir(&preprocessed_path_b);
                let start = Instant::now();
                preprocess_parquet(&parquet_path_b, &preprocessed_path_b)
                    .expect("preprocess parquet");
                println!("preprocess_ms: {}", start.elapsed().as_millis());
            }

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
            if is_join {
                ensure_dir(&oracle_path_b);
                let start = Instant::now();
                let runner = CommitBuilder::new()
                    .with_parquet_path(preprocessed_path_b.clone())
                    .with_pk_path(pk_path.clone())
                    .with_output_path(Some(oracle_path_b.clone()))
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
            let query_sql = if is_join {
                let table_name_b = preprocessed_path_b
                    .file_stem()
                    .and_then(|name| name.to_str())
                    .expect("parquet path must have a file stem");
                query
                    .sql
                    .replace("{table1}", table_name)
                    .replace("{table2}", table_name_b)
            } else {
                query.sql.replace("{table}", table_name)
            };

            let start = Instant::now();
            let runner = ProveBuilder::new()
                .with_query(query_sql.clone())
                .with_parquet_paths(if is_join {
                    vec![preprocessed_path.clone(), preprocessed_path_b.clone()]
                } else {
                    vec![preprocessed_path.clone()]
                })
                .with_oracle_paths(if is_join {
                    vec![oracle_path.clone(), oracle_path_b.clone()]
                } else {
                    vec![oracle_path.clone()]
                })
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
                .with_parquet_paths(if is_join {
                    vec![preprocessed_path.clone(), preprocessed_path_b.clone()]
                } else {
                    vec![preprocessed_path.clone()]
                })
                .with_oracle_paths(if is_join {
                    vec![oracle_path.clone(), oracle_path_b.clone()]
                } else {
                    vec![oracle_path.clone()]
                })
                .with_proof_path(proof_path.clone())
                .with_vk_path(vk_path.clone())
                .build()
                .expect("build verify");
            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            rt.block_on(runner.run()).expect("tt verify");
            println!("verify_ms: {}", start.elapsed().as_millis());
            println!("----------------------------------------");
        }
    }
}

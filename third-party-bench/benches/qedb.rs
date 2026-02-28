use std::path::Path;

use qedb::bench::benchmark_parquet_once_cached;
use tpch_data::preprocess_parquet;

// Paths for input/output artifacts.
const PARQUET_DIR: &str = "artifact";
const PARQUET_SUBDIR_PREFIX: &str = "size_";
const PARQUET_FILE_PREFIX: &str = "bench_table_";

// Table sizes as powers of two.
const TABLE_POWS: &[u32] = &[10, 14, 18];

struct QuerySpec {
    name: &'static str,
    dir: &'static str,
    sql: &'static str,
}

// Query strings (SQL). `{table}` will be replaced with the parquet file stem.
const QUERIES: &[QuerySpec] = &[
    QuerySpec {
        name: "filter",
        dir: "filter",
        sql: "SELECT * FROM {table} WHERE a = 1 AND b = 2",
    },
    QuerySpec {
        name: "aggregate_count",
        dir: "aggregate_count",
        sql: "SELECT COUNT(b) FROM {table}",
    },
];

fn parquet_paths(
    bench_root: &Path,
    pow: u32,
    query_dir: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = bench_root
        .join(PARQUET_DIR)
        .join(format!("{PARQUET_SUBDIR_PREFIX}{pow}"));
    let query_dir = dir.join(query_dir);
    let parquet = query_dir.join(format!("{PARQUET_FILE_PREFIX}{pow}.parquet"));
    let preprocessed = query_dir.join(format!("{PARQUET_FILE_PREFIX}{pow}_preprocessed.parquet"));
    (parquet, preprocessed)
}

fn main() {
    let bench_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    println!("table_sizes: {:?}", TABLE_POWS);

    for &pow in TABLE_POWS {
        for query in QUERIES {
            let (parquet_path, preprocessed_path) =
                parquet_paths(bench_root, pow, query.dir);

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
            let query_sql = query.sql.replace("{table}", table_name);

            println!("pow: {pow} query: {}", query.name);
            let cache_root = bench_root
                .join(PARQUET_DIR)
                .join(format!("{PARQUET_SUBDIR_PREFIX}{pow}"))
                .join("qedb_cache");
            std::fs::create_dir_all(&cache_root).expect("create qedb cache dir");

            let cache_dir = cache_root.join(query.name);
            std::fs::create_dir_all(&cache_dir).expect("create query cache dir");

            let output = benchmark_parquet_once_cached(
                preprocessed_path.to_string_lossy().as_ref(),
                &query_sql,
                &cache_dir,
            )
            .expect("qedb bench");

            println!("prove_ms: {}", output.prove_ms);
            println!("verify_ms: {}", output.verify_ms);
            println!("proof_bytes: {}", output.proof_bytes);
            println!("----------------------------------------");
        }
    }
}

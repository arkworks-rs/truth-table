use std::{
    path::{Path, PathBuf},
    time::Instant,
};

use exec::{
    prove::ProveBuilder,
    setup::SetupBuilder,
    test_utils::resolve_oracle_path_blocking,
    verify::VerifyBuilder,
};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use tpch_data::preprocess_parquet;
use tracing::Metadata;
use tracing_subscriber::{filter::filter_fn, fmt::format::FmtSpan, prelude::*, EnvFilter};
use tracing_tree::HierarchicalLayer;
use std::sync::OnceLock;

#[path = "../../exec/benches/support/stats_layer.rs"]
mod stats_layer;

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
const TABLE_POWS: &[u32] = &[10, 14, 18, 22];

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
        sql: "SELECT count(*) FROM {table}",
    },
    QuerySpec {
        name: "join",
        dir: "Join",
        sql: "SELECT {table1}.a, {table2}.a FROM {table1} JOIN {table2} ON {table1}.a = {table2}.a",
    },
    QuerySpec {
        name: "limit_offset",
        dir: "Limit_Offset",
        sql: "SELECT * FROM {table} LIMIT 10",
    },
];

fn ensure_dir(path: &Path) {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)
        .unwrap_or_else(|err| panic!("failed to create directory {}: {err}", dir.display()));
}

fn parquet_paths_for(
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
    init_bench_tracing();
    let bench_root = Path::new(env!("CARGO_MANIFEST_DIR"));

    println!("table_sizes: {:?}", TABLE_POWS);

    for &pow in TABLE_POWS {
        for query in QUERIES {
            let is_join = query.name == "join";
            let table_size = 1usize << pow;
            let (parquet_path, preprocessed_path) =
                parquet_paths_for(bench_root, pow, query.dir, JOIN_TABLE_PREFIX_A);
            let (parquet_path_b, preprocessed_path_b) = if is_join {
                parquet_paths_for(bench_root, pow, query.dir, JOIN_TABLE_PREFIX_B)
            } else {
                (std::path::PathBuf::new(), std::path::PathBuf::new())
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
            let mut log_size = (total_rows.max(1) as f64).log2().ceil() as usize;
            if is_join {
                let base = (total_rows.max(1) as f64).log2().ceil() as usize;
                log_size = (base + 1).max(16);
            }
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

            let start = Instant::now();
            let oracle_path =
                resolve_oracle_path_blocking(&preprocessed_path, &pk_path).expect("resolve oracle");
            println!("commit_ms: {}", start.elapsed().as_millis());
            let oracle_path_b = if is_join {
                let start = Instant::now();
                let oracle =
                    resolve_oracle_path_blocking(&preprocessed_path_b, &pk_path)
                        .expect("resolve oracle");
                println!("commit_ms: {}", start.elapsed().as_millis());
                oracle
            } else {
                std::path::PathBuf::new()
            };

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
            let _query_span =
                tracing::info_span!(target: "bench_stats", "bench_query", query = %query_sql)
                    .entered();

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

fn init_bench_tracing() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        // Default to off; honor RUST_LOG when set.
        let rust_log = std::env::var("RUST_LOG").unwrap_or_default();
        let mut filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));
        if !rust_log.contains("datafusion") {
            filter = filter.add_directive("datafusion=off".parse().expect("datafusion directive"));
            filter = filter.add_directive("datafusion_=off".parse().expect("datafusion directive"));
        }
        if !rust_log.contains("sqlparser") {
            filter = filter.add_directive("sqlparser=off".parse().expect("sqlparser directive"));
        }
        filter = filter.add_directive(
            "bench_stats=info"
                .parse()
                .expect("bench stats directive"),
        );

        let tree_layer = HierarchicalLayer::default()
            .with_targets(false)
            .with_timer(tracing_tree::time::Uptime::default())
            .with_deferred_spans(true)
            .with_writer(std::io::stdout)
            .with_filter(filter_fn(|metadata: &Metadata<'_>| {
                metadata.is_span() && metadata.target() != "bench_stats"
            }));

        let span_timing_layer = tracing_subscriber::fmt::layer()
            .with_span_events(FmtSpan::CLOSE)
            .with_timer(tracing_subscriber::fmt::time::Uptime::default())
            .with_target(false)
            .with_filter(filter_fn(|metadata: &Metadata<'_>| {
                metadata.is_span() && metadata.target() != "bench_stats"
            }));

        let stats_csv_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(|root| root.join("exec").join("target").join("bench_stats.csv"))
            .unwrap_or_else(|| PathBuf::from(stats_layer::BENCH_STATS_CSV_PATH));

        let stats_layer = match stats_layer::BenchStatsCsvLayer::new(stats_csv_path.clone()) {
            Ok(layer) => Some(layer),
            Err(err) => {
                eprintln!(
                    "failed to initialize bench stats csv layer at {}: {}",
                    stats_csv_path.display(),
                    err
                );
                None
            }
        };

        let registry = tracing_subscriber::registry()
            .with(filter)
            .with(tree_layer)
            .with(span_timing_layer);

        if let Some(stats_layer) = stats_layer {
            let _ = registry.with(stats_layer).try_init();
        } else {
            let _ = registry.try_init();
        }
    });
}

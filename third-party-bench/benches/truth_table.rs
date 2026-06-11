use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use arrow::{
    array::{ArrayRef, Int64Array},
    datatypes::{DataType, Field, Schema},
    record_batch::RecordBatch,
};
use exec::{
    prove::ProveBuilder,
    setup::SetupBuilder,
    test_utils::resolve_oracle_path_blocking,
    verify::VerifyBuilder,
};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use tpch_data::preprocess_parquet;
use tracing::Metadata;
use tracing_subscriber::{filter::filter_fn, fmt::format::FmtSpan, prelude::*, EnvFilter};
use tracing_tree::HierarchicalLayer;
use std::sync::OnceLock;

#[path = "../../crates/tt-exec/benches/support/stats_layer.rs"]
mod stats_layer;

mod proof_stats {
    use std::path::Path;

    use ark_piop::types::artifact::SizeBreakdown;
    use exec::backend::BenchBackend;
    use front_end::structs::{Artifact, TTProof};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    type B = BenchBackend;

    /// Read the proof and result parquet from disk and emit the same
    /// `proof_size`/`results` tracing fields the TPC-H bench harness emits.
    /// Without this the third-party JSONL is missing those keys and the
    /// dashboard's Proof Size / Results tabs show "n/a".
    pub fn emit_proof_and_result_stats(query: &str, proof_path: &Path, result_path: &Path) {
        let snark_proof = match <TTProof<B> as Artifact>::load(proof_path) {
            Ok(p) => p,
            Err(err) => {
                eprintln!(
                    "proof_stats: failed to load proof at {}: {err:?}",
                    proof_path.display()
                );
                return;
            }
        };

        let crypto = snark_proof
            .as_snark_proof()
            .to_bytes()
            .expect("serialize crypto proof");
        let cryptographic = crypto.len();
        let non_cryptographic = bincode::serialize(snark_proof.optimization_hints())
            .expect("serialize optimization hints")
            .len();
        let full_compressed = snark_proof
            .to_bytes()
            .expect("serialize compressed proof")
            .len();
        let crypto_compressed = zstd::encode_all(std::io::Cursor::new(&crypto), 1)
            .expect("zstd compress crypto proof")
            .len();
        let mv_count = snark_proof
            .as_snark_proof()
            .mv_pcs_subproof
            .unique_comitments
            .len();
        let uv_count = snark_proof
            .as_snark_proof()
            .uv_pcs_subproof
            .unique_comitments
            .len();
        let breakdown = snark_proof
            .as_snark_proof()
            .size_breakdown()
            .expect("size_breakdown");

        super::stats_layer::emit_proof_size_bytes(
            query,
            cryptographic,
            non_cryptographic,
            cryptographic + non_cryptographic,
            full_compressed,
            child(&breakdown, "sc_subproof"),
            child(&breakdown, "mv_pcs_subproof"),
            grand(&breakdown, "mv_pcs_subproof", "opening_proof"),
            grand(&breakdown, "mv_pcs_subproof", "commitments"),
            mv_count,
            grand(&breakdown, "mv_pcs_subproof", "query_map"),
            child(&breakdown, "uv_pcs_subproof"),
            grand(&breakdown, "uv_pcs_subproof", "opening_proof"),
            grand(&breakdown, "uv_pcs_subproof", "commitments"),
            uv_count,
            grand(&breakdown, "uv_pcs_subproof", "query_map"),
            child(&breakdown, "miscellaneous_field_elements"),
            effective_num_threads(),
            crypto_compressed,
        );

        if let Ok(file) = std::fs::File::open(result_path)
            && let Ok(builder) = ParquetRecordBatchReaderBuilder::try_new(file)
        {
            let metadata = builder.metadata();
            let rows = metadata.file_metadata().num_rows() as usize;
            let schema_str = builder
                .schema()
                .fields()
                .iter()
                .map(|f| format!("{}: {}", f.name(), f.data_type()))
                .collect::<Vec<_>>()
                .join(", ");
            let size = std::fs::metadata(result_path)
                .map(|m| m.len() as usize)
                .unwrap_or(0);
            super::stats_layer::emit_results_stats(query, rows, &schema_str, size);
        }
    }

    fn child(b: &SizeBreakdown, key: &str) -> usize {
        b.parts.get(key).map(|p| p.size).unwrap_or(0)
    }

    fn grand(b: &SizeBreakdown, key: &str, child_key: &str) -> usize {
        b.parts
            .get(key)
            .and_then(|p| p.parts.get(child_key))
            .map(|c| c.size)
            .unwrap_or(0)
    }

    fn effective_num_threads() -> usize {
        std::env::var("RAYON_NUM_THREADS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1)
            })
    }
}

// Paths for input/output artifacts.
const PARQUET_DIR: &str = "artifact";
const PARQUET_SUBDIR_PREFIX: &str = "size_";
const PARQUET_FILE_PREFIX: &str = "bench_table_";
const JOIN_TABLE_PREFIX_A: &str = "bench_table";
const JOIN_TABLE_PREFIX_B: &str = "bench_table_2";
const ORACLE_DIR: &str = "artifact";
const PK_FILENAME_PREFIX: &str = "tt_pk_";
const VK_FILENAME_PREFIX: &str = "tt_vk_";

// Table sizes as powers of two. Keep in sync with the matching arrays in
// `sxt_proof_of_sql.rs` and `qedb.rs` so all three systems sweep the same
// (query, size) grid.
const TABLE_POWS: &[u32] = &[16, 17, 18, 19];

struct QuerySpec {
    name: &'static str,
    dir: &'static str,
    sql: &'static str,
}

// Query strings (SQL). `{table}` will be replaced with the parquet file stem.
// Keep this list in sync with the matching `QUERIES` slice in
// `sxt_proof_of_sql.rs` and `qedb.rs`.
const QUERIES: &[QuerySpec] = &[
    QuerySpec {
        name: "filter",
        dir: "filter",
        sql: "SELECT a, b, c, d FROM {table} WHERE a = 1 AND b = 2",
    },
    QuerySpec {
        name: "aggregate_count",
        dir: "aggregate_count",
        sql: "SELECT count(b) FROM {table}",
    },
    QuerySpec {
        name: "join",
        dir: "Join",
        sql: "SELECT {table1}.a AS a1, {table2}.a AS a2 FROM {table1}, {table2} WHERE {table1}.a = {table2}.a",
    },
    QuerySpec {
        name: "join_pk_fk",
        dir: "Join_PK_FK",
        sql: "SELECT {table1}.a AS a1, {table2}.a_fk AS a2 FROM {table1}, {table2} WHERE {table1}.a = {table2}.a_fk",
    },
    QuerySpec {
        name: "limit_offset",
        dir: "Limit_Offset",
        sql: "SELECT \"column\" FROM {table} LIMIT 10",
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

fn is_join_query(query: &QuerySpec) -> bool {
    matches!(query.name, "join" | "join_pk_fk")
}

#[allow(dead_code)]

fn parquet_row_count(path: &Path) -> usize {
    let raw_file =
        File::open(path).unwrap_or_else(|err| panic!("failed to open parquet {}: {err}", path.display()));
    let builder = ParquetRecordBatchReaderBuilder::try_new(raw_file).expect("parquet reader");
    builder.metadata().file_metadata().num_rows() as usize
}

#[allow(dead_code)]
fn parquet_has_column(path: &Path, column_name: &str) -> bool {
    let Ok(file) = File::open(path) else {
        return false;
    };
    let Ok(builder) = ParquetRecordBatchReaderBuilder::try_new(file) else {
        return false;
    };
    builder
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == column_name)
}

#[allow(dead_code)]
fn write_bigint_parquet(path: &Path, column_name: &str, values: Vec<i64>) {
    ensure_dir(path);
    let schema = Arc::new(Schema::new(vec![Field::new(
        column_name,
        DataType::Int64,
        false,
    )]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![Arc::new(Int64Array::from(values)) as ArrayRef],
    )
    .expect("record batch");
    let file =
        File::create(path).unwrap_or_else(|err| panic!("failed to create parquet {}: {err}", path.display()));
    let mut writer = ArrowWriter::try_new(file, schema, None).expect("arrow writer");
    writer.write(&batch).expect("write parquet batch");
    writer.close().expect("close parquet writer");
}

#[allow(dead_code)]
fn write_join_pk_fk_constraints(path: &Path, pow: u32) {
    ensure_dir(path);
    let left_table = format!("bench_table_{pow}_preprocessed");
    let right_table = format!("bench_table_2_{pow}_preprocessed");
    let payload = format!(
        concat!(
            "{{\n",
            "  \"format_version\": 1,\n",
            "  \"source\": \"third-party-bench-join-pk-fk\",\n",
            "  \"tables\": [\n",
            "    {{\n",
            "      \"table\": \"{left_table}\",\n",
            "      \"primary_key\": [\"a\"],\n",
            "      \"unique_keys\": [],\n",
            "      \"foreign_keys\": []\n",
            "    }},\n",
            "    {{\n",
            "      \"table\": \"{right_table}\",\n",
            "      \"primary_key\": [],\n",
            "      \"unique_keys\": [],\n",
            "      \"foreign_keys\": [{{\n",
            "        \"columns\": [\"a_fk\"],\n",
            "        \"ref_table\": \"{left_table}\",\n",
            "        \"ref_columns\": [\"a\"]\n",
            "      }}]\n",
            "    }}\n",
            "  ]\n",
            "}}\n"
        ),
        left_table = left_table,
        right_table = right_table,
    );
    std::fs::write(path, payload)
        .unwrap_or_else(|err| panic!("failed to write constraints {}: {err}", path.display()));
}

#[allow(dead_code)]
fn ensure_join_pk_fk_artifacts(bench_root: &Path, pow: u32) {
    let (source_left, _) = parquet_paths_for(bench_root, pow, "Join", JOIN_TABLE_PREFIX_A);
    let (source_right, _) = parquet_paths_for(bench_root, pow, "Join", JOIN_TABLE_PREFIX_B);
    let (target_left, target_left_preprocessed) =
        parquet_paths_for(bench_root, pow, "Join_PK_FK", JOIN_TABLE_PREFIX_A);
    let (target_right, target_right_preprocessed) =
        parquet_paths_for(bench_root, pow, "Join_PK_FK", JOIN_TABLE_PREFIX_B);
    let constraints_path = bench_root
        .join(PARQUET_DIR)
        .join(format!("{PARQUET_SUBDIR_PREFIX}{pow}"))
        .join("Join_PK_FK")
        .join("constraints.json");

    // Self-heal: if an earlier run wrote target_right with the old "a" column,
    // wipe every artifact that depended on it so the regeneration below picks
    // up the new "a_fk" schema.
    if target_right.exists() && !parquet_has_column(&target_right, "a_fk") {
        for stale in [
            &target_right,
            &target_right_preprocessed,
            &target_right.with_extension("oracle"),
            &target_right_preprocessed.with_extension("oracle"),
            &constraints_path,
        ] {
            let _ = std::fs::remove_file(stale);
        }
    }

    if target_left.exists() && target_right.exists() && constraints_path.exists() {
        return;
    }
    if !source_left.exists() || !source_right.exists() {
        panic!(
            "missing source join parquet(s) at {} and/or {}. Generate Join artifacts first.",
            source_left.display(),
            source_right.display()
        );
    }

    let left_rows = parquet_row_count(&source_left);
    let right_rows = parquet_row_count(&source_right);
    let pk_values = (0..left_rows).map(|idx| idx as i64).collect::<Vec<_>>();
    let fk_values = (0..right_rows)
        .map(|idx| (idx / 2).min(left_rows.saturating_sub(1)) as i64)
        .collect::<Vec<_>>();

    if !target_left.exists() {
        write_bigint_parquet(&target_left, "a", pk_values);
    }
    if !target_right.exists() {
        write_bigint_parquet(&target_right, "a_fk", fk_values);
    }
    if !constraints_path.exists() {
        write_join_pk_fk_constraints(&constraints_path, pow);
    }
}

fn main() {
    init_bench_tracing();
    let bench_root = Path::new(env!("CARGO_MANIFEST_DIR"));

    println!("curve: {}", exec::backend::BACKEND_NAME);
    println!("table_sizes: {:?}", TABLE_POWS);

    for &pow in TABLE_POWS {
        for query in QUERIES {
            let is_join = is_join_query(query);
            let _table_size = 1usize << pow;
            if query.name == "join_pk_fk" {
                ensure_join_pk_fk_artifacts(bench_root, pow);
            }
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
                .join(format!("bench_{}.proof", exec::backend::BACKEND_NAME));

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
                .join(format!(
                    "{PK_FILENAME_PREFIX}{log_size}_{}.pk",
                    exec::backend::BACKEND_NAME
                ));
            let vk_path = bench_root
                .join(PARQUET_DIR)
                .join(format!("{PARQUET_SUBDIR_PREFIX}{pow}"))
                .join(format!(
                    "{VK_FILENAME_PREFIX}{log_size}_{}.vk",
                    exec::backend::BACKEND_NAME
                ));

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
            let prove_outputs = rt.block_on(runner.run()).expect("tt prove");
            let prove_ms = start.elapsed().as_millis();
            let proof_size = std::fs::metadata(&proof_path)
                .map(|meta| meta.len())
                .unwrap_or(0);
            println!("prove_ms: {}", prove_ms);
            println!("proof_bytes: {}", proof_size);
            proof_stats::emit_proof_and_result_stats(
                &query_sql,
                &prove_outputs.proof_path,
                &prove_outputs.result_path,
            );

            let start = Instant::now();
            let runner = VerifyBuilder::new()
                .with_query(query_sql)
                .with_oracle_paths(if is_join {
                    vec![oracle_path.clone(), oracle_path_b.clone()]
                } else {
                    vec![oracle_path.clone()]
                })
                .with_proof_path(proof_path.clone())
                .with_result_path(prove_outputs.result_path.clone())
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

        let stats_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(|root| {
                root.join("tt-results")
                    .join("raw")
                    .join("bench_stats_third_party_tt.jsonl")
            })
            .unwrap_or_else(|| PathBuf::from(stats_layer::BENCH_STATS_JSONL_PATH));

        let stats_layer = match stats_layer::BenchStatsJsonlLayer::new(stats_path.clone()) {
            Ok(layer) => Some(layer),
            Err(err) => {
                eprintln!(
                    "failed to initialize bench stats jsonl layer at {}: {}",
                    stats_path.display(),
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

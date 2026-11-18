use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
    time::Instant,
};

use exec::{
    commit::CommitBuilder, prove::ProveBuilder, setup::SetupBuilder, verify::VerifyBuilder,
};
use tpch_data::preprocess_parquet;
use tracing::Metadata;
use tracing_subscriber::{EnvFilter, filter::filter_fn, fmt::format::FmtSpan, prelude::*};
use tracing_tree::HierarchicalLayer;
use tt_third_party_bench::micro;

#[path = "../../crates/tt-exec/benches/support/stats_layer.rs"]
mod stats_layer;

mod proof_stats {
    use std::path::Path;

    use ark_piop::types::artifact::SizeBreakdown;
    use exec::backend::BenchBackend;
    use front_end::structs::{Artifact, TTProof};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    type B = BenchBackend;

    /// Emits the `proof_size`/`results` tracing fields the TPC-H bench harness
    /// emits, read from the proof and result parquet on disk. Without them
    /// the dashboard's Proof Size / Results tabs show "n/a".
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
            grand(&breakdown, "mv_pcs_subproof", "constants"),
            grand(&breakdown, "mv_pcs_subproof", "query_map"),
            child(&breakdown, "uv_pcs_subproof"),
            grand(&breakdown, "uv_pcs_subproof", "opening_proof"),
            grand(&breakdown, "uv_pcs_subproof", "commitments"),
            uv_count,
            grand(&breakdown, "uv_pcs_subproof", "constants"),
            grand(&breakdown, "uv_pcs_subproof", "query_map"),
            child(&breakdown, "miscellaneous_field_elements"),
            child(&breakdown, "miscellaneous_field_vectors"),
            child(&breakdown, "logup_gkr_subproofs"),
            child(&breakdown, "lookup_messages"),
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
            // No in-memory result here to preview; the dashboard reads the
            // preview from the parquet path when it needs one.
            super::stats_layer::emit_results_stats(
                query,
                rows,
                &schema_str,
                size,
                "",
                &result_path.to_string_lossy(),
            );
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

// Proving and verifying keys are shared by every query of a log size.
const KEY_DIR: &str = "artifact/micro";

fn main() {
    init_bench_tracing();
    let bench_root = Path::new(env!("CARGO_MANIFEST_DIR"));

    println!("curve: {}", exec::backend::BACKEND_NAME);
    let pows = micro::table_pows();
    println!("table_sizes: {pows:?}");
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    // Setup time per key size; each size's keys are generated once per run.
    let mut setups: std::collections::HashMap<usize, f64> = std::collections::HashMap::new();

    for pow in pows {
        for query in micro::QUERIES.iter().filter(|q| micro::selected(q)) {
            let parquets = micro::ensure_parquets(bench_root, pow, query, "_preprocessed");
            let dir = micro::query_dir(bench_root, pow, query);
            let preprocessed: Vec<PathBuf> = parquets
                .iter()
                .map(|p| p.with_file_name(format!("{}_preprocessed.parquet", stem(p))))
                .collect();
            let proof_path = dir.join(format!("bench_{}.proof", exec::backend::BACKEND_NAME));
            // Two tables of 2^pow rows each need keys one size up, and no key
            // is under 2^16: a query can open a 16-variable polynomial
            // whatever the table size.
            let log_size = (pow as usize + usize::from(parquets.len() > 1)).max(16);
            let key = |prefix: &str, ext: &str| {
                bench_root.join(KEY_DIR).join(format!(
                    "{prefix}{log_size}_{}.{ext}",
                    exec::backend::BACKEND_NAME
                ))
            };
            let (pk_path, vk_path) = (key("tt_pk_", "pk"), key("tt_vk_", "vk"));

            println!(
                "pow: {pow} query: {} parquet_rows: {} log_size: {log_size}",
                query.name,
                1u64 << pow
            );

            let setup_ms = *setups.entry(log_size).or_insert_with(|| {
                let start = Instant::now();
                SetupBuilder::new()
                    .with_size_label(Some(log_size.to_string()))
                    .with_pk_path(Some(pk_path.clone()))
                    .with_vk_path(Some(vk_path.clone()))
                    .build()
                    .expect("build setup")
                    .run()
                    .expect("tt setup");
                start.elapsed().as_secs_f64() * 1e3
            });
            println!("setup_ms: {setup_ms:.3}");
            println!("pk_bytes: {}", file_len(&pk_path));
            println!("vk_bytes: {}", file_len(&vk_path));

            // The data owner's work: padding each table with its activator
            // column, then committing it.
            let start = Instant::now();
            for (raw, pre) in parquets.iter().zip(&preprocessed) {
                preprocess_parquet(raw, pre).expect("preprocess parquet");
            }
            println!("preprocess_ms: {:.3}", start.elapsed().as_secs_f64() * 1e3);
            let (mut commit_ms, mut commitment_bytes) = (0.0, 0);
            let oracle_paths: Vec<PathBuf> = preprocessed
                .iter()
                .map(|pre| {
                    let (oracle, elapsed) = rt
                        .block_on(
                            CommitBuilder::new()
                                .with_parquet_path(pre.clone())
                                .with_pk_path(pk_path.clone())
                                .with_output_path(Some(pre.with_extension("oracle")))
                                .build()
                                .expect("build commit")
                                .run_with_timing(),
                        )
                        .expect("tt commit");
                    commit_ms += elapsed.as_secs_f64() * 1e3;
                    commitment_bytes +=
                        file_len(&oracle) + file_len(&exec::paths::fingerprint_bins_path(&oracle));
                    oracle
                })
                .collect();
            println!("commit_ms: {commit_ms:.3}");
            println!("commitment_bytes: {commitment_bytes}");

            let names: Vec<String> = preprocessed.iter().map(|p| stem(p)).collect();
            let query_sql =
                micro::sql(query, &names.iter().map(String::as_str).collect::<Vec<_>>());
            let _query_span =
                tracing::info_span!(target: "bench_stats", "bench_query", query = %query_sql)
                    .entered();

            let start = Instant::now();
            let runner = ProveBuilder::new()
                .with_query(query_sql.clone())
                .with_parquet_paths(preprocessed.clone())
                .with_oracle_paths(oracle_paths.clone())
                .with_pk_path(pk_path.clone())
                .with_output_path(Some(proof_path.clone()))
                .build()
                .expect("build prove");
            let prove_outputs = rt.block_on(runner.run()).expect("tt prove");
            println!("prove_ms: {:.3}", start.elapsed().as_secs_f64() * 1e3);
            println!(
                "proof_bytes: {}",
                std::fs::metadata(&proof_path).map_or(0, |m| m.len())
            );
            proof_stats::emit_proof_and_result_stats(
                &query_sql,
                &prove_outputs.proof_path,
                &prove_outputs.result_path,
            );

            let verify_ms = micro::verify_median_ms(|| {
                let runner = VerifyBuilder::new()
                    .with_query(query_sql.clone())
                    .with_oracle_paths(oracle_paths.clone())
                    .with_proof_path(proof_path.clone())
                    .with_result_path(prove_outputs.result_path.clone())
                    .with_vk_path(vk_path.clone())
                    .build()
                    .expect("build verify");
                rt.block_on(runner.run()).expect("tt verify");
            });
            println!("verify_ms: {verify_ms:.3}");
            println!("result_rows: {}", parquet_rows(&prove_outputs.result_path));
            println!("----------------------------------------");
        }
    }
}

fn parquet_rows(path: &Path) -> i64 {
    let file = std::fs::File::open(path).expect("open result parquet");
    parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(file)
        .expect("result parquet")
        .metadata()
        .file_metadata()
        .num_rows()
}

fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).map_or(0, |m| m.len())
}

fn stem(path: &Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .expect("parquet file stem")
        .to_string()
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
        filter = filter.add_directive("bench_stats=info".parse().expect("bench stats directive"));

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

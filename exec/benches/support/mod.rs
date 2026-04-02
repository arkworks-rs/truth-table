use std::{
    collections::{HashMap, HashSet},
    fmt,
    fs::File,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
};

mod stats_layer;

use anyhow::{Context, Result};
use ark_piop::{DefaultSnarkBackend, verifier::ArgVerifier};
use ark_serialize::CanonicalDeserialize;
use datafusion::{
    config::ConfigOptions,
    optimizer::{Analyzer, Optimizer, OptimizerContext},
    datasource::MemTable,
    prelude::{ParquetReadOptions, SessionConfig, SessionContext},
};
use exec::{
    prove::ProveBuilder,
    setup::DEFAULT_BENCH_LOG_SIZE,
    test_utils::{resolve_key_paths, resolve_oracle_path_blocking},
};
use front_end::{
    prover::TTProver,
    shared::TTSharedConfig,
    structs::{Artifact, TTProof, TTVk},
    verifier::{TTVerifier, TTVerifierConfig},
};
use indexmap::IndexMap;
use tokio::runtime::Runtime;
use tt_core::ctx_oracles::CtxOracles;
use tt_core::irs::shared_ir::GadgetPlannedIr;

pub use stats_layer::emit_benchmark_stats_row;

pub type B = DefaultSnarkBackend;

#[derive(Clone, Copy, Debug)]
pub struct BenchCase {
    pub name: &'static str,
    pub query: &'static str,
    pub tables: &'static [&'static str],
}

impl fmt::Display for BenchCase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[derive(Clone, Debug)]
pub struct BenchAssets {
    pub case: BenchCase,
    pub parquet_paths: Vec<PathBuf>,
    pub oracle_paths: Vec<PathBuf>,
    pub pk_path: PathBuf,
    pub vk_path: PathBuf,
}

pub struct BenchProof {
    pub proof: TTProof<B>,
    // Serialized SNARK proof component of TTProof.
    pub snark_proof_bytes: usize,
    // Serialized optimized IR component of TTProof.
    pub optimized_ir_bytes: usize,
}

pub struct VerifierFullBenchState {
    pub verifier: TTVerifier<B>,
    pub query: String,
    pub proof: TTProof<B>,
    pub output_memtable: Arc<MemTable>,
    pub preprocessed_gadget_ir: Mutex<Option<Arc<GadgetPlannedIr<B>>>>,
}

pub struct ProverBenchIteration {
    pub prover: TTProver<B>,
    pub query: String,
}

static PROOF_CACHE: OnceLock<Mutex<HashMap<&'static str, Arc<BenchProof>>>> = OnceLock::new();
static PROOF_SIZE_LOGGED: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
static ASSETS_CACHE: OnceLock<Mutex<HashMap<&'static str, BenchAssets>>> = OnceLock::new();

pub fn init_bench_tracing() {
    // Install a bench-focused subscriber that honors RUST_LOG for stdout.
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        use tracing_subscriber::EnvFilter;
        use tracing_subscriber::filter::filter_fn;
        use tracing_subscriber::fmt::format::FmtSpan;
        use tracing_subscriber::prelude::*;

        // Default to info, and always suppress DataFusion unless explicitly requested.
        let rust_log = std::env::var("RUST_LOG").unwrap_or_default();
        let mut filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));
        if !rust_log.contains("datafusion") {
            filter = filter.add_directive(
                "datafusion=off"
                    .parse()
                    .expect("parse datafusion directive"),
            );
            filter = filter.add_directive(
                "datafusion_=off"
                    .parse()
                    .expect("parse datafusion directive"),
            );
        }
        if !rust_log.contains("sqlparser") {
            filter =
                filter.add_directive("sqlparser=off".parse().expect("parse sqlparser directive"));
        }
        // Keep bench stats events enabled even when the default log level is off.
        filter = filter.add_directive(
            "bench_stats=info"
                .parse()
                .expect("parse bench stats directive"),
        );

        // Use tracing-tree for hierarchical spans in bench logs.
        let tree_layer = tracing_tree::HierarchicalLayer::default()
            .with_targets(false)
            .with_timer(tracing_tree::time::Uptime::default())
            // .with_indent_lines(true)
            .with_deferred_spans(true)
            .with_writer(std::io::stdout)
            .with_filter(filter_fn(|metadata| {
                metadata.is_span() && metadata.target() != "bench_stats"
            }));

        // Emit span close events with elapsed time so span durations are visible.
        let span_timing_layer = tracing_subscriber::fmt::layer()
            .with_span_events(FmtSpan::CLOSE)
            .with_timer(tracing_subscriber::fmt::time::Uptime::default())
            .with_target(false)
            .with_filter(filter_fn(|metadata| {
                metadata.is_span() && metadata.target() != "bench_stats"
            }));

        // Emit regular events (e.g. debug!/info! logs) alongside span output.
        let event_layer = tracing_subscriber::fmt::layer()
            .with_timer(tracing_subscriber::fmt::time::Uptime::default())
            .with_target(false)
            .with_filter(filter_fn(|metadata| {
                metadata.is_event() && metadata.target() != "bench_stats"
            }));

        let stats_layer = match stats_layer::BenchStatsCsvLayer::new_default() {
            Ok(layer) => Some(layer),
            Err(err) => {
                eprintln!(
                    "failed to initialize bench stats csv layer at {}: {}",
                    stats_layer::default_csv_path().display(),
                    err
                );
                None
            }
        };

        let registry = tracing_subscriber::registry()
            .with(filter)
            .with(tree_layer)
            .with(span_timing_layer)
            .with(event_layer);

        if let Some(stats_layer) = stats_layer {
            let _ = registry.with(stats_layer).try_init();
        } else {
            let _ = registry.try_init();
        }
    });
}

pub fn prepare_assets(case: BenchCase) -> BenchAssets {
    // Resolve parquet/oracle paths and keys once per benchmark case.
    assert!(
        !case.tables.is_empty(),
        "bench queries must reference at least one table"
    );

    let parquet_paths = case
        .tables
        .iter()
        .map(|name| tpch_data::bench_data_path(format!("{name}.parquet")))
        .collect::<Vec<_>>();

    let (pk_path, vk_path) =
        resolve_key_paths(DEFAULT_BENCH_LOG_SIZE).expect("resolve proving/verifying keys");

    let oracle_paths = parquet_paths
        .iter()
        .map(|parquet_path| {
            resolve_oracle_path_blocking(parquet_path, &pk_path)
                .expect("resolve oracle path for bench")
        })
        .collect::<Vec<_>>();

    BenchAssets {
        case,
        parquet_paths,
        oracle_paths,
        pk_path,
        vk_path,
    }
}

pub fn prepare_assets_cached(case: BenchCase) -> BenchAssets {
    let cache = ASSETS_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock().expect("bench assets cache poisoned");

    if let Some(existing) = guard.get(case.name).cloned() {
        return existing;
    }

    let assets = prepare_assets(case);
    guard.insert(case.name, assets.clone());
    assets
}

pub fn run_prover_once(assets: &BenchAssets) -> TTProof<B> {
    // Build the prover and run proof generation once (used for warmup/caching).
    let iteration = prepare_prover_iteration(assets);
    run_prover_iteration(iteration)
}

pub fn prepare_prover_iteration(assets: &BenchAssets) -> ProverBenchIteration {
    // Build a fresh prover instance outside the timed region.
    let runner = ProveBuilder::new()
        .with_query(assets.case.query.to_string())
        .with_parquet_paths(assets.parquet_paths.clone())
        .with_oracle_paths(assets.oracle_paths.clone())
        .with_pk_path(assets.pk_path.clone())
        .build()
        .expect("prepare prover runner for bench");

    let prover = block_on(runner.build_tt_prover()).expect("build prover for bench");

    ProverBenchIteration {
        prover,
        query: assets.case.query.to_string(),
    }
}

pub fn run_prover_iteration(iteration: ProverBenchIteration) -> TTProof<B> {
    // Time only the proving call to avoid counting setup.
    let _query_span =
        tracing::info_span!(target: "bench_stats", "bench_query", query = %iteration.query)
            .entered();
    let (_table, snark_proof) =
        block_on(iteration.prover.prove(&iteration.query)).expect("prove for bench");
    stats_layer::emit_proof_commitment_counts(
        snark_proof.as_inner().mv_pcs_subproof.comitments.len(),
        snark_proof.as_inner().uv_pcs_subproof.comitments.len(),
    );
    let cryptographic_proof_size_bytes = snark_proof.snark_proof_serialized_size_bytes();
    let non_cryptographic_proof_size_bytes = snark_proof
        .optimized_ir_serialized_size_bytes()
        .expect("serialize optimized ir for bench size accounting");
    stats_layer::emit_proof_size_bytes(
        &iteration.query,
        cryptographic_proof_size_bytes,
        non_cryptographic_proof_size_bytes,
        cryptographic_proof_size_bytes + non_cryptographic_proof_size_bytes,
    );
    snark_proof
}

pub fn ensure_proof(assets: &BenchAssets) -> Arc<BenchProof> {
    // Fetch a cached proof; callers should warm the cache first.
    let cache = PROOF_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    cache
        .lock()
        .expect("bench proof cache poisoned")
        .get(assets.case.name)
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "missing cached proof for {}; run warmup_proof first",
                assets.case.name
            )
        })
}

pub fn warmup_proof(assets: &BenchAssets) -> Arc<BenchProof> {
    // Precompute and cache a proof outside the timed verifier benchmark.
    let cache = PROOF_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(existing) = cache
        .lock()
        .expect("bench proof cache poisoned")
        .get(assets.case.name)
        .cloned()
    {
        return existing;
    }

    let proof = run_prover_once(assets);
    let bench_proof = save_proof(assets.case.name, &proof);

    cache
        .lock()
        .expect("bench proof cache poisoned")
        .insert(assets.case.name, Arc::clone(&bench_proof));

    bench_proof
}

pub fn cache_proof_in_memory_if_absent(
    case_name: &'static str,
    proof: &TTProof<B>,
) -> Arc<BenchProof> {
    let cache = PROOF_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock().expect("bench proof cache poisoned");

    if let Some(existing) = guard.get(case_name).cloned() {
        return existing;
    }

    let bench_proof = Arc::new(BenchProof {
        proof: proof.clone(),
        snark_proof_bytes: proof.snark_proof_serialized_size_bytes(),
        optimized_ir_bytes: proof
            .optimized_ir_serialized_size_bytes()
            .expect("serialize optimized ir for bench size accounting"),
    });
    guard.insert(case_name, Arc::clone(&bench_proof));
    bench_proof
}

pub fn save_proof(_case_name: &str, proof: &TTProof<B>) -> Arc<BenchProof> {
    let snark_proof_bytes = proof.snark_proof_serialized_size_bytes();
    let optimized_ir_bytes = proof
        .optimized_ir_serialized_size_bytes()
        .expect("serialize optimized ir for bench size accounting");

    Arc::new(BenchProof {
        proof: proof.clone(),
        snark_proof_bytes,
        optimized_ir_bytes,
    })
}

pub fn log_proof_size_once(case_name: &'static str, _query: &'static str, proof: &BenchProof) {
    // Print proof size once per case to avoid noisy benchmark output.
    let logged = PROOF_SIZE_LOGGED.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = logged.lock().expect("bench proof size log poisoned");
    if guard.insert(case_name) {
        let full_bytes = proof.snark_proof_bytes + proof.optimized_ir_bytes;
        println!(
            "proof size ({}) core={} ({} bytes) plan={} ({} bytes) full={} ({} bytes)",
            case_name,
            format_bytes(proof.snark_proof_bytes),
            proof.snark_proof_bytes,
            format_bytes(proof.optimized_ir_bytes),
            proof.optimized_ir_bytes,
            format_bytes(full_bytes),
            full_bytes,
        );
    }
}

pub fn build_verifier_full_state_from_proof(
    assets: &BenchAssets,
    proof: &TTProof<B>,
) -> VerifierFullBenchState {
    // Build verifier/proof once so timed iterations include only IR passes + crypto verification.
    let verifier = build_verifier(assets);
    let prover_iteration = prepare_prover_iteration(assets);
    let output_memtable = block_on(prover_iteration.prover.output_memtable(&prover_iteration.query))
        .expect("extract output memtable from prover for bench");
    build_verifier_full_state_from_proof_impl(
        verifier,
        assets.case.query,
        proof.clone(),
        output_memtable,
    )
}

fn build_verifier_full_state_from_proof_impl(
    verifier: TTVerifier<B>,
    query: &str,
    proof: TTProof<B>,
    output_memtable: Arc<MemTable>,
) -> VerifierFullBenchState {
    VerifierFullBenchState {
        verifier,
        query: query.to_string(),
        proof,
        output_memtable,
        preprocessed_gadget_ir: Mutex::new(None),
    }
}

pub fn run_full_verifier_once(state: &VerifierFullBenchState) {
    // Time full frontend verification path: IR passes + argument verification.
    let cached_ir = state
        .preprocessed_gadget_ir
        .lock()
        .expect("preprocessed ir lock poisoned")
        .clone();
    if let Some(gadget_planned_ir) = cached_ir {
        block_on_verifier(
            state
                .verifier
                .verify_with_preprocessed_and_output(
                    &state.proof,
                    gadget_planned_ir.as_ref(),
                    Arc::clone(&state.output_memtable),
                ),
        )
        .expect("verify for bench");
    } else {
        block_on_verifier(state.verifier.verify(
            &state.query,
            &state.proof,
            Arc::clone(&state.output_memtable),
        ))
            .expect("verify for bench");
    }
}

pub fn run_preprocess_once(state: &VerifierFullBenchState) {
    // Time only one-time verifier preprocessing (planning/gadget planning cache fill).
    let gadget_planned_ir = state.verifier.preprocess_query(&state.query, &state.proof);
    *state
        .preprocessed_gadget_ir
        .lock()
        .expect("preprocessed ir lock poisoned") = Some(Arc::new(gadget_planned_ir));
}

fn build_verifier(assets: &BenchAssets) -> TTVerifier<B> {
    // Mirror the CLI verifier setup so bench verification matches production.
    let ctx = SessionContext::new_with_config(SessionConfig::new().with_target_partitions(1));
    for parquet_path in &assets.parquet_paths {
        let table_name = parquet_path
            .file_stem()
            .expect("parquet path must have a file name")
            .to_string_lossy()
            .to_string();

        block_on_verifier(ctx.register_parquet(
            &table_name,
            parquet_path.to_str().expect("parquet path must be UTF-8"),
            ParquetReadOptions::default(),
        ))
        .expect("register parquet for bench");
    }

    let oracles = assets
        .oracle_paths
        .iter()
        .map(load_oracle)
        .collect::<Result<Vec<_>>>()
        .expect("load oracles for bench");
    let ctx_oracles = ctx_oracles_from_oracles(&assets.parquet_paths, &oracles)
        .expect("build ctx oracles for bench");

    let tt_vk = TTVk::<B>::load(&assets.vk_path).expect("load verifying key for bench");
    let arg_verifier = ArgVerifier::new_from_vk(tt_vk.into_inner());

    let shared_config = build_shared_config(ctx, ctx_oracles);
    TTVerifier::new(TTVerifierConfig::default(), shared_config, arg_verifier)
}

fn load_oracle(path: &PathBuf) -> Result<arithmetic::table_oracle::ArithTableOracle<B>> {
    // Load oracle files saved by the commit step.
    let file = File::open(path)
        .with_context(|| format!("failed to open oracle file {}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    arithmetic::table_oracle::ArithTableOracle::<B>::deserialize_compressed(&mut reader)
        .context("failed to deserialize oracle")
}

fn ctx_oracles_from_oracles(
    parquet_paths: &[PathBuf],
    oracles: &[arithmetic::table_oracle::ArithTableOracle<B>],
) -> Result<CtxOracles<B>> {
    // Build the oracle map keyed by schema.
    let mut table_oracles = IndexMap::new();
    let mut named_oracles = IndexMap::new();
    for (path, oracle) in parquet_paths.iter().zip(oracles.iter()) {
        let schema = oracle
            .schema()
            .ok_or_else(|| anyhow::anyhow!("oracle does not provide a schema"))?;
        let table_name = path
            .file_stem()
            .ok_or_else(|| anyhow::anyhow!("parquet {} missing file stem", path.display()))?
            .to_string_lossy()
            .to_string();
        table_oracles.insert(schema, oracle.clone());
        named_oracles.insert(table_name, oracle.clone());
    }
    Ok(CtxOracles::with_named_oracles(table_oracles, named_oracles))
}

fn build_shared_config(
    session_ctx: SessionContext,
    ctx_oracles: CtxOracles<B>,
) -> TTSharedConfig<B> {
    // Use the same planner/optimizer wiring as production verification.
    TTSharedConfig::new(
        Analyzer::with_rules(proof_planner::logical_plan_analyzer::rules()),
        Optimizer::with_rules(proof_planner::logical_plan_optimizer::rules(&session_ctx)),
        ctx_oracles,
        session_ctx,
        ConfigOptions::new(),
        OptimizerContext::new(),
        |_plan_after_rule, _rule| {},
    )
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    // Use a fresh runtime per helper invocation to avoid cross-case task-local
    // or executor state leaking across benchmark cases in the same process.
    let rt = Runtime::new().expect("build tokio runtime");
    rt.block_on(future)
}

fn block_on_verifier<F: std::future::Future>(future: F) -> F::Output {
    // Verifier benchmarks intentionally use a single-thread runtime so IR passes
    // and DataFusion async work do not spill across multiple executor threads.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build single-thread verifier runtime")
        .block_on(future)
}

fn format_bytes(byte_len: usize) -> String {
    // Human-readable byte sizes for proof output.
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = byte_len as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{byte_len} {}", UNITS[unit])
    } else {
        format!("{size:.2} {}", UNITS[unit])
    }
}

use std::{
    collections::{HashMap, HashSet},
    fmt,
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
};

use anyhow::{Context, Result};
use ark_piop::{DefaultSnarkBackend, prover::structs::proof::SNARKProof, verifier::ArgVerifier};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use datafusion::{config::ConfigOptions, optimizer::{Analyzer, Optimizer, OptimizerContext}, prelude::{ParquetReadOptions, SessionContext}};
use front_end::{shared::TTSharedConfig, structs::{Artifact, TTProof, TTVk}, verifier::{TTVerifier, TTVerifierConfig}};
use indexmap::IndexMap;
use tempfile::TempDir;
use tokio::runtime::Runtime;
use tt_core::ctx_oracles::CtxOracles;

use exec::{prove::ProveBuilder, setup::DEFAULT_BENCH_LOG_SIZE, test_utils::{resolve_key_paths, resolve_oracle_path_blocking}};

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

#[derive(Debug)]
pub struct BenchProof {
    pub proof_path: PathBuf,
    pub proof_bytes: Vec<u8>,
    _temp_dir: TempDir,
}

pub struct VerifierBenchState {
    pub assets: BenchAssets,
    pub proof_bytes: Vec<u8>,
}

static PROOF_CACHE: OnceLock<Mutex<HashMap<&'static str, Arc<BenchProof>>>> = OnceLock::new();
static PROOF_SIZE_LOGGED: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();

pub fn init_bench_tracing() {
    // Install a bench-focused subscriber that honors RUST_LOG for stdout.
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        use tracing_subscriber::EnvFilter;

        // Default to info, and always suppress DataFusion unless explicitly requested.
        let rust_log = std::env::var("RUST_LOG").unwrap_or_default();
        let mut filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        if !rust_log.contains("datafusion") {
            filter = filter.add_directive("datafusion=off".parse().expect("parse datafusion directive"));
            filter = filter.add_directive("datafusion_=off".parse().expect("parse datafusion directive"));
        }
        if !rust_log.contains("sqlparser") {
            filter = filter.add_directive("sqlparser=off".parse().expect("parse sqlparser directive"));
        }

        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .try_init();
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
        .map(|name| {
            tpch_data::bench_data_path(format!("{name}.parquet"))
        })
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

pub fn run_prover_once(assets: &BenchAssets) -> TTProof<B> {
    // Build a fresh prover per bench iteration to avoid stateful reuse.
    let runner = ProveBuilder::new()
        .with_query(assets.case.query.to_string())
        .with_parquet_paths(assets.parquet_paths.clone())
        .with_oracle_paths(assets.oracle_paths.clone())
        .with_pk_path(assets.pk_path.clone())
        .build()
        .expect("prepare prover runner for bench");

    let prover = block_on(runner.build_tt_prover()).expect("build prover for bench");
    let (_table, snark_proof) =
        block_on(prover.prove(assets.case.query)).expect("prove for bench");
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

pub fn save_proof(case_name: &str, proof: &TTProof<B>) -> Arc<BenchProof> {
    // Persist the proof bytes in a temp file for reuse in verifier benches.
    let temp_dir = TempDir::new().expect("create temp dir for bench proof");
    let proof_path = temp_dir.path().join(format!("{case_name}.proof.pi"));

    let mut proof_bytes = Vec::new();
    proof
        .as_inner()
        .serialize_uncompressed(&mut proof_bytes)
        .expect("serialize proof for bench");

    let file = File::create(&proof_path).expect("create proof file for bench");
    let mut writer = BufWriter::new(file);
    writer
        .write_all(&proof_bytes)
        .expect("write proof bytes for bench");
    writer.flush().expect("flush proof bytes for bench");

    Arc::new(BenchProof {
        proof_path,
        proof_bytes,
        _temp_dir: temp_dir,
    })
}

pub fn cache_proof(case_name: &'static str, proof: Arc<BenchProof>) {
    // Store a proof in the global bench cache.
    let cache = PROOF_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    cache
        .lock()
        .expect("bench proof cache poisoned")
        .insert(case_name, proof);
}

pub fn log_proof_size_once(case_name: &'static str, byte_len: usize) {
    // Print proof size once per case to avoid noisy benchmark output.
    let logged = PROOF_SIZE_LOGGED.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = logged.lock().expect("bench proof size log poisoned");
    if guard.insert(case_name) {
        println!(
            "proof size ({}): {}",
            case_name,
            format_bytes(byte_len)
        );
    }
}

pub fn build_verifier_state(assets: &BenchAssets, proof_bytes: Vec<u8>) -> VerifierBenchState {
    // Bundle the assets and proof bytes for repeated verifier iterations.
    VerifierBenchState {
        assets: assets.clone(),
        proof_bytes,
    }
}

pub fn run_verifier_once(state: &VerifierBenchState) {
    // Build a fresh verifier per bench iteration to avoid stateful reuse.
    let verifier = build_verifier(&state.assets);
    let proof = proof_from_bytes(&state.proof_bytes);
    block_on(verifier.verify(state.assets.case.query, proof)).expect("verify for bench");
}

fn build_verifier(assets: &BenchAssets) -> TTVerifier<B> {
    // Mirror the CLI verifier setup so bench verification matches production.
    let ctx = SessionContext::new();
    for parquet_path in &assets.parquet_paths {
        let table_name = parquet_path
            .file_stem()
            .expect("parquet path must have a file name")
            .to_string_lossy()
            .to_string();

        block_on(
            ctx.register_parquet(
                &table_name,
                parquet_path
                    .to_str()
                    .expect("parquet path must be UTF-8"),
                ParquetReadOptions::default(),
            ),
        )
        .expect("register parquet for bench");
    }

    let oracles = assets
        .oracle_paths
        .iter()
        .map(|path| load_oracle(path))
        .collect::<Result<Vec<_>>>()
        .expect("load oracles for bench");
    let ctx_oracles = ctx_oracles_from_oracles(&oracles).expect("build ctx oracles for bench");

    let tt_vk =
        TTVk::<B>::load(&assets.vk_path).expect("load verifying key for bench");
    let arg_verifier = ArgVerifier::new_from_vk(tt_vk.into_inner());

    let shared_config = build_shared_config(ctx, ctx_oracles);
    TTVerifier::new(TTVerifierConfig::default(), shared_config, arg_verifier)
}

fn proof_from_bytes(bytes: &[u8]) -> TTProof<B> {
    // Deserialize proof bytes into the front-end wrapper.
    let mut reader = std::io::Cursor::new(bytes);
    let proof =
        SNARKProof::<B>::deserialize_uncompressed(&mut reader).expect("deserialize proof bytes");
    TTProof::new(proof)
}

fn load_oracle(path: &PathBuf) -> Result<arithmetic::table_oracle::ArithTableOracle<B>> {
    // Load oracle files saved by the commit step.
    let file = File::open(path)
        .with_context(|| format!("failed to open oracle file {}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    arithmetic::table_oracle::ArithTableOracle::<B>::deserialize_uncompressed(&mut reader)
        .context("failed to deserialize oracle")
}

fn ctx_oracles_from_oracles(
    oracles: &[arithmetic::table_oracle::ArithTableOracle<B>],
) -> Result<CtxOracles<B>> {
    // Build the oracle map keyed by schema.
    let mut table_oracles = IndexMap::new();
    for oracle in oracles {
        let schema = oracle
            .schema()
            .ok_or_else(|| anyhow::anyhow!("oracle does not provide a schema"))?;
        table_oracles.insert(schema, oracle.clone());
    }
    Ok(CtxOracles::new(table_oracles))
}

fn build_shared_config(
    session_ctx: SessionContext,
    ctx_oracles: CtxOracles<B>,
) -> TTSharedConfig<B> {
    // Use the same planner/optimizer wiring as production verification.
    TTSharedConfig::new(
        Analyzer::with_rules(proof_planner::logical_plan_analyzer::rules()),
        Optimizer::with_rules(proof_planner::logical_plan_optimizer::rules()),
        ctx_oracles,
        session_ctx,
        ConfigOptions::new(),
        OptimizerContext::new(),
        |_plan_after_rule, _rule| {},
    )
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    // Reuse a single Tokio runtime for benchmark helpers.
    static RT: OnceLock<Runtime> = OnceLock::new();
    let rt = RT.get_or_init(|| Runtime::new().expect("build tokio runtime"));
    rt.block_on(future)
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

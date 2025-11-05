use std::{
    fmt,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use divan::black_box;
use exec::{
    prove::{PreparedProverArtifacts, build_proof_from_artifacts, prepare_prover_artifacts},
    test_utils::{resolve_key_paths, resolve_oracle_path},
};
use tokio::runtime::Runtime;
use tpch_data::{bench_data_path, query_spec};

#[derive(Clone, Copy, Debug)]
struct BenchQuery {
    name: &'static str,
    query: &'static str,
    tables: &'static [&'static str],
}

impl fmt::Display for BenchQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

const DUMMY_QUERY: &str = "SELECT l_orderkey FROM lineitem WHERE l_linenumber = 1";
const DUMMY_TABLES: &[&str] = &["lineitem"];

fn prover_bench_queries() -> &'static [BenchQuery] {
    static QUERIES: OnceLock<&'static [BenchQuery]> = OnceLock::new();
    QUERIES.get_or_init(|| {
        let tpch = query_spec(1);
        let queries = vec![
            BenchQuery {
                name: "tpch_q1",
                query: tpch.sql,
                tables: tpch.tables,
            },
            // BenchQuery {
            //     name: "lineitem_dummy",
            //     query: DUMMY_QUERY,
            //     tables: DUMMY_TABLES,
            // },
        ];
        Box::leak(queries.into_boxed_slice())
    })
}

#[derive(Debug)]
struct ProverBenchInputs {
    spec: BenchQuery,
    runtime: Arc<Runtime>,
    parquet_paths: Vec<PathBuf>,
    oracle_paths: Vec<PathBuf>,
    pk_path: PathBuf,
}

struct ProverBenchIteration {
    artifacts: PreparedProverArtifacts,
}

fn prepare_prover_inputs(spec: BenchQuery) -> ProverBenchInputs {
    let runtime = Arc::new(Runtime::new().expect("failed to create tokio runtime"));
    assert!(
        !spec.tables.is_empty(),
        "bench queries must reference at least one table"
    );
    let (pk_path, _) = resolve_key_paths(exec::setup::DEFAULT_BENCH_LOG_SIZE)
        .expect("resolve proving/verifying keys");

    let parquet_paths = spec
        .tables
        .iter()
        .map(|table| parquet_path_for_table(table))
        .collect::<Vec<_>>();

    let mut oracle_paths = Vec::with_capacity(parquet_paths.len());
    for parquet_path in &parquet_paths {
        let oracle_path = runtime
            .block_on(resolve_oracle_path(parquet_path, &pk_path))
            .expect("resolve oracle path for bench");
        oracle_paths.push(oracle_path);
    }

    ProverBenchInputs {
        spec,
        runtime,
        parquet_paths,
        oracle_paths,
        pk_path,
    }
}

fn prepare_iteration_state(inputs: ProverBenchInputs) -> ProverBenchIteration {
    let artifacts = inputs
        .runtime
        .block_on(prepare_prover_artifacts(
            inputs.spec.query,
            &inputs.parquet_paths,
            &inputs.oracle_paths,
            Some(inputs.pk_path.as_path()),
        ))
        .expect("prepare prover artifacts for benchmark");

    ProverBenchIteration { artifacts }
}

#[divan::bench(args = prover_bench_queries(), max_time = 60)]
fn prove_command(bencher: divan::Bencher, spec: BenchQuery) {
    bencher
        .with_inputs(move || prepare_iteration_state(prepare_prover_inputs(spec)))
        .bench_local_values(run_prove_iteration);
}

fn run_prove_iteration(iteration: ProverBenchIteration) {
    let proof = build_proof_from_artifacts(iteration.artifacts)
        .expect("execute prove backend for benchmark");

    black_box(proof);
}

fn parquet_path_for_table(table: &str) -> PathBuf {
    let path = bench_data_path(format!("{table}.parquet"));
    assert!(
        path.exists(),
        "missing bench parquet {}. Run `cargo run --bin download-data --package tpch-data` to fetch it.",
        path.display()
    );
    path
}

fn main() {
    divan::main();
}

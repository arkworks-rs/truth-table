use std::{fmt, future::Future, path::PathBuf, sync::OnceLock};

use crate::support::emit_benchmark_stats_row;
use divan::black_box;
use front_end::prover::TTProver;
use tokio::runtime::Runtime;
use tpch_data::{bench_data_path, query_spec};
use tt_exec::{
    backend::BenchBackend,
    prove::ProveBuilder,
    setup::DEFAULT_BENCH_LOG_SIZE,
    test_utils::{resolve_key_paths, resolve_oracle_path_blocking},
};

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

fn prover_bench_queries() -> &'static [BenchQuery] {
    // Static list of queries to benchmark for the prover-only bench.
    static QUERIES: OnceLock<&'static [BenchQuery]> = OnceLock::new();
    QUERIES.get_or_init(|| {
        let tpch = query_spec(1, false);
        let queries = vec![BenchQuery {
            name: "tpch_q1",
            query: tpch.sql,
            tables: tpch.tables,
        }];
        Box::leak(queries.into_boxed_slice())
    })
}

#[derive(Debug)]
struct ProverBenchInputs {
    spec: BenchQuery,
    parquet_paths: Vec<PathBuf>,
    oracle_paths: Vec<PathBuf>,
    pk_path: PathBuf,
}

struct ProverBenchIteration {
    prover: TTProver<BenchBackend>,
    query: &'static str,
}

fn prepare_prover_inputs(spec: BenchQuery) -> ProverBenchInputs {
    // Resolve parquet/oracle paths and keys for a single prover benchmark case.
    assert!(
        !spec.tables.is_empty(),
        "bench queries must reference at least one table"
    );
    let (pk_path, _) =
        resolve_key_paths(DEFAULT_BENCH_LOG_SIZE).expect("resolve proving/verifying keys");

    let parquet_paths = spec
        .tables
        .iter()
        .map(|table| parquet_path_for_table(table))
        .collect::<Vec<_>>();

    let oracle_paths = parquet_paths
        .iter()
        .map(|parquet_path| {
            resolve_oracle_path_blocking(parquet_path, &pk_path)
                .expect("resolve oracle path for bench")
        })
        .collect::<Vec<_>>();

    ProverBenchInputs {
        spec,
        parquet_paths,
        oracle_paths,
        pk_path,
    }
}

fn prepare_iteration_state(inputs: ProverBenchInputs) -> ProverBenchIteration {
    // Build a TTProver instance for one benchmark iteration.
    let runner = ProveBuilder::new()
        .with_query(inputs.spec.query.to_string())
        .with_parquet_paths(inputs.parquet_paths)
        .with_oracle_paths(inputs.oracle_paths)
        .with_pk_path(inputs.pk_path)
        .build()
        .expect("prepare prover runner for benchmark");

    let prover = block_on(runner.build_tt_prover()).expect("build prover for benchmark");

    ProverBenchIteration {
        prover,
        query: inputs.spec.query,
    }
}

#[divan::bench(args = prover_bench_queries(), max_time = 1)]
fn prove_command(bencher: divan::Bencher, spec: BenchQuery) {
    // Benchmark a single prover execution per iteration.
    bencher
        .with_inputs(move || prepare_iteration_state(prepare_prover_inputs(spec)))
        .bench_local_values(run_prove_iteration);
    emit_benchmark_stats_row("prove_command", spec.name);
}

fn run_prove_iteration(iteration: ProverBenchIteration) {
    // Run proof generation once and black-box the output to keep work alive.
    let _query_span =
        tracing::info_span!(target: "bench_stats", "bench_query", query = iteration.query)
            .entered();
    let (_table, proof) =
        block_on(iteration.prover.prove(iteration.query)).expect("prove for benchmark");
    black_box(proof);
}

fn block_on<F: Future>(future: F) -> F::Output {
    // Reuse a single Tokio runtime for benchmark helpers.
    static RT: OnceLock<Runtime> = OnceLock::new();
    let rt = RT.get_or_init(|| Runtime::new().expect("build tokio runtime"));
    rt.block_on(future)
}

fn parquet_path_for_table(table: &str) -> PathBuf {
    // Resolve the parquet path for the benchmark dataset.
    let path = bench_data_path(format!("{table}.parquet"));
    assert!(
        path.exists(),
        "missing bench parquet {}. Run `cargo run --bin download-data --package tpch-data` to fetch it.",
        path.display()
    );
    path
}

// Bench registration is handled by `benches.rs`.

use std::{
    fmt,
    path::PathBuf,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use divan::black_box;
use exec::{
    cmd::{
        Runnable,
        common::{OracleArg, ParquetArg, QueryArg},
        prove::Prove,
    },
    test_utils::{resolve_key_paths, resolve_oracle_path},
};
use tempfile::TempDir;
use tokio::runtime::Runtime;
use tpch_data::{bench_data_path, query_spec};

#[derive(Clone, Copy, Debug)]
struct BenchQuery {
    name: &'static str,
    query: &'static str,
    tables: &'static [&'static str],
}

impl BenchQuery {
    fn primary_table(&self) -> &str {
        self.tables
            .first()
            .expect("bench queries must reference at least one table")
    }
}

impl fmt::Display for BenchQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

const DUMMY_QUERY: &str =
    "SELECT l_orderkey FROM lineitem WHERE l_linenumber = 1 ORDER BY l_orderkey";
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
    parquet_path: PathBuf,
    oracle_path: PathBuf,
    _key_paths: (PathBuf, PathBuf),
    temp_dir: TempDir,
}

fn prepare_prover_inputs(spec: BenchQuery) -> ProverBenchInputs {
    let runtime = Arc::new(Runtime::new().expect("failed to create tokio runtime"));
    let key_paths = resolve_key_paths(exec::setup::DEFAULT_BENCH_LOG_SIZE)
        .expect("resolve proving/verifying keys");
    let parquet_path = parquet_path_for_table(spec.primary_table());
    let oracle_path = runtime
        .block_on(resolve_oracle_path(&parquet_path, &key_paths.0))
        .expect("resolve oracle path for bench");
    let temp_dir = TempDir::new().expect("create temporary directory for proofs");

    ProverBenchInputs {
        spec,
        runtime,
        parquet_path,
        oracle_path,
        _key_paths: key_paths,
        temp_dir,
    }
}

#[divan::bench(args = prover_bench_queries(), max_time = 60)]
fn prove_command(bencher: divan::Bencher, spec: BenchQuery) {
    bencher
        .with_inputs(move || prepare_prover_inputs(spec))
        .bench_local_values(|inputs| run_prove_iteration(inputs));
}

fn run_prove_iteration(inputs: ProverBenchInputs) {
    static PROOF_COUNTER: AtomicUsize = AtomicUsize::new(0);
    let ProverBenchInputs {
        spec,
        runtime,
        parquet_path,
        oracle_path,
        temp_dir,
        ..
    } = inputs;

    let proof_path = temp_dir.path().join(format!(
        "proof_{}.bin",
        PROOF_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));

    let command = Prove {
        query: QueryArg {
            query: spec.query.to_owned(),
        },
        parquet: ParquetArg {
            parquet: parquet_path.clone(),
        },
        oracle: OracleArg {
            oracle: oracle_path.clone(),
        },
        output_path: Some(proof_path.clone()),
        timed: false,
    };

    runtime
        .block_on(command.run())
        .expect("execute prove command for benchmark");

    black_box(&proof_path);

    let _ = std::fs::remove_file(&proof_path);
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

use std::{
    fmt,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use divan::black_box;
use exec::{
    cmd::{
        Runnable,
        common::{OracleArg, ParquetArg, QueryArg},
        prove::Prove,
        verify::Verify,
    },
    test_utils::{resolve_key_paths, resolve_oracle_path},
};
use tempfile::TempDir;
use tokio::runtime::Runtime;
use tpch_data::{bench_data_path, query_spec};

#[derive(Clone, Copy)]
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
    "SELECT COUNT(*) FROM lineitem WHERE l_shipmode = 'AIR' OR l_shipmode = 'FOB'";
const DUMMY_TABLES: &[&str] = &["lineitem"];

fn verifier_bench_queries() -> &'static [BenchQuery] {
    static QUERIES: OnceLock<&'static [BenchQuery]> = OnceLock::new();
    QUERIES.get_or_init(|| {
        let tpch = query_spec(1);
        let queries = vec![
            BenchQuery {
                name: "tpch_q1",
                query: tpch.sql,
                tables: tpch.tables,
            },
            BenchQuery {
                name: "lineitem_dummy",
                query: DUMMY_QUERY,
                tables: DUMMY_TABLES,
            },
        ];
        Box::leak(queries.into_boxed_slice())
    })
}

struct VerifierBenchInputs {
    spec: BenchQuery,
    runtime: Arc<Runtime>,
    parquet_path: PathBuf,
    oracle_path: PathBuf,
    vk_path: PathBuf,
    proof_path: PathBuf,
    _temp_dir: TempDir,
}

fn prepare_verifier_inputs(spec: BenchQuery) -> VerifierBenchInputs {
    let runtime = Arc::new(Runtime::new().expect("failed to create tokio runtime"));
    let (pk_path, vk_path) = resolve_key_paths(exec::setup::DEFAULT_BENCH_LOG_SIZE)
        .expect("resolve proving/verifying keys for bench");
    let parquet_path = parquet_path_for_table(spec.primary_table());
    let oracle_path = runtime
        .block_on(resolve_oracle_path(&parquet_path, &pk_path))
        .expect("resolve oracle path for bench");
    let temp_dir = TempDir::new().expect("create temporary directory for proofs");
    let proof_path = temp_dir.path().join("bench_proof.bin");

    let prove_cmd = Prove {
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
        .block_on(prove_cmd.run())
        .expect("generate proof artifact for verifier bench");

    VerifierBenchInputs {
        spec,
        runtime,
        parquet_path,
        oracle_path,
        vk_path,
        proof_path,
        _temp_dir: temp_dir,
    }
}

#[divan::bench(args = verifier_bench_queries(), max_time = 60)]
fn verify_command(bencher: divan::Bencher, spec: BenchQuery) {
    bencher
        .with_inputs(move || prepare_verifier_inputs(spec))
        .bench_local_values(|inputs| run_verify_iteration(inputs));
}

fn run_verify_iteration(inputs: VerifierBenchInputs) {
    let VerifierBenchInputs {
        spec,
        runtime,
        parquet_path,
        oracle_path,
        vk_path,
        proof_path,
        ..
    } = inputs;

    let verify_cmd = Verify {
        query: QueryArg {
            query: spec.query.to_owned(),
        },
        parquet: ParquetArg {
            parquet: parquet_path,
        },
        oracle: OracleArg {
            oracle: oracle_path,
        },
        proof: proof_path.clone(),
        vk_path,
        timed: false,
    };

    runtime
        .block_on(verify_cmd.run())
        .expect("execute verify command for benchmark");

    black_box(&proof_path);
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

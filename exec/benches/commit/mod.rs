use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

use arithmetic::{
    ROW_ID_COL_NAME,
    table_oracle::{ArithTableOracle, TrackedTableOracle},
};
use ark_piop::{DefaultSnarkBackend, prover::ArgProver, verifier::ArgVerifier};
use ark_serialize::CanonicalSerialize;
use datafusion::prelude::{ParquetReadOptions, SessionContext};
use divan::Bencher;
use exec::{setup::DEFAULT_BENCH_LOG_SIZE, test_utils::resolve_key_paths};
use front_end::{
    prover::{TTProver, TTProverConfig},
    shared::TTSharedConfig,
    structs::{Artifact, TTPk},
};
use tokio::runtime::Runtime;
use tt_core::prover::passes::materialization::configure_constraint_metadata_from_parquet_paths;

use crate::support::{B, emit_benchmark_stats_row};

#[derive(Clone, Copy, Debug)]
struct CommitCase {
    name: &'static str,
    table: &'static str,
}

const TPCH_TABLES: &[CommitCase] = &[
    CommitCase {
        name: "commit_region",
        table: "region",
    },
    CommitCase {
        name: "commit_nation",
        table: "nation",
    },
    CommitCase {
        name: "commit_part",
        table: "part",
    },
    CommitCase {
        name: "commit_supplier",
        table: "supplier",
    },
    CommitCase {
        name: "commit_partsupp",
        table: "partsupp",
    },
    CommitCase {
        name: "commit_customer",
        table: "customer",
    },
    CommitCase {
        name: "commit_orders",
        table: "orders",
    },
    CommitCase {
        name: "commit_lineitem",
        table: "lineitem",
    },
];

fn commit_cases() -> &'static [CommitCase] {
    TPCH_TABLES
}

fn commit_pk_path() -> &'static PathBuf {
    static PK_PATH: OnceLock<PathBuf> = OnceLock::new();
    PK_PATH.get_or_init(|| {
        let (pk_path, _vk_path) = resolve_key_paths(DEFAULT_BENCH_LOG_SIZE)
            .expect("resolve proving key for commit bench");
        pk_path
    })
}

fn log_commit_size_once(case_name: &'static str, bytes: usize) {
    static LOGGED: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let logged = LOGGED.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = logged.lock().expect("commit size log poisoned");
    if guard.insert(case_name) {
        println!(
            "tracked table oracle size ({}) = {} bytes",
            case_name, bytes
        );
    }
}

fn commit_content_len(case: CommitCase) -> usize {
    let parquet_path = tpch_data::bench_data_path(format!("{}.parquet", case.table));
    configure_constraint_metadata_from_parquet_paths(std::slice::from_ref(&parquet_path));
    let table_name = case.table;
    let query = format!("SELECT * EXCEPT ({ROW_ID_COL_NAME}) FROM {table_name}");
    let ctx = SessionContext::new();

    block_on(
        ctx.register_parquet(
            table_name,
            parquet_path
                .to_str()
                .expect("parquet path for commit bench must be valid UTF-8"),
            ParquetReadOptions::default(),
        ),
    )
    .expect("register parquet for commit bench");

    let tt_pk = TTPk::<B>::load(commit_pk_path()).expect("load proving key for commit bench");
    let snark_pk = tt_pk.into_inner();
    let mut verifier = ArgVerifier::<DefaultSnarkBackend>::new_from_vk(snark_pk.vk.clone());
    let prover = ArgProver::<DefaultSnarkBackend>::new_from_pk(snark_pk);
    let shared_config: TTSharedConfig<B> = TTSharedConfig::with_defaults(ctx);
    let prover = TTProver::new(TTProverConfig::for_commit(), shared_config, prover);
    let (table_scan_table, proof) =
        block_on(prover.prove_with_table_scan(&query)).expect("prove with table-scan");
    verifier.set_proof(proof.snark_proof());

    let tracked_oracle = TrackedTableOracle::from_tracked_table(table_scan_table, &mut verifier)
        .expect("convert tracked table to oracle");
    let serializable = ArithTableOracle::<B>::from_tracked_table_oracle(&tracked_oracle);
    let mut oracle_bytes = Vec::new();
    serializable
        .serialize_compressed(&mut oracle_bytes)
        .expect("serialize oracle content");
    log_commit_size_once(case.name, oracle_bytes.len());
    oracle_bytes.len()
}

#[divan::bench(args = commit_cases(), max_time = 2)]
fn bench_tpch_commit_content(bencher: Bencher, case: CommitCase) {
    bencher.bench_local(|| {
        divan::black_box(commit_content_len(case));
    });
    emit_benchmark_stats_row("bench_tpch_commit_content", case.name);
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    static RT: OnceLock<Runtime> = OnceLock::new();
    let rt = RT.get_or_init(|| Runtime::new().expect("build tokio runtime"));
    rt.block_on(future)
}

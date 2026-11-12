use std::{
    collections::HashSet,
    sync::{Mutex, OnceLock},
};
use tt_core::session::session_context;

use arithmetic::{ROW_ID_COL_NAME, fingerprint::NUM_BINS};
use ark_piop::setup::structs::SNARKPk;
use ark_serialize::CanonicalSerialize;
use datafusion::prelude::ParquetReadOptions;
use divan::Bencher;
use front_end::{
    data_owner::{TTDataOwner, TTDataOwnerConfig},
    shared::TTSharedConfig,
    structs::{Artifact, TTPk},
};
use tokio::runtime::Runtime;
use tt_core::irs::nodes::hints::configure_constraint_metadata_from_parquet_paths;
use tt_exec::{setup::DEFAULT_BENCH_LOG_SIZE, test_utils::resolve_key_paths};

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

/// Loaded once, before any timed sample: reading the key from disk is not
/// part of committing a table.
fn commit_pk() -> SNARKPk<B> {
    static PK: OnceLock<SNARKPk<B>> = OnceLock::new();
    PK.get_or_init(|| {
        let (pk_path, _vk_path) = resolve_key_paths(DEFAULT_BENCH_LOG_SIZE)
            .expect("resolve proving key for commit bench");
        TTPk::<B>::load(&pk_path)
            .expect("load proving key for commit bench")
            .into_inner()
    })
    .clone()
}

fn log_commit_size_once(case_name: &'static str, white_box: bool, bytes: usize) {
    static LOGGED: OnceLock<Mutex<HashSet<(&'static str, bool)>>> = OnceLock::new();
    let logged = LOGGED.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = logged.lock().expect("commit size log poisoned");
    if guard.insert((case_name, white_box)) {
        let suffix = if white_box { "_tt_2" } else { "" };
        println!("tracked table oracle size ({case_name}{suffix}) = {bytes} bytes");
    }
}

/// Commits `case`'s table as the hash-only tables when `white_box` is off,
/// as the `_tt_2` tables otherwise, building their fingerprint rules as
/// `tt commit` does.
fn commit_content_len(case: CommitCase, white_box: bool) -> usize {
    let parquet_path = tpch_data::bench_data_path(format!("{}.parquet", case.table));
    configure_constraint_metadata_from_parquet_paths(std::slice::from_ref(&parquet_path));
    let table_name = case.table;
    let query = format!("SELECT * EXCEPT ({ROW_ID_COL_NAME}) FROM {table_name}");
    let ctx = session_context();

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
    if white_box {
        let rules = block_on(tt_exec::commit::column_rules(&ctx, table_name, NUM_BINS))
            .expect("fingerprint rules for commit bench");
        arithmetic::fingerprint::configure_rules(rules).expect("install fingerprint rules");
    }

    let snark_pk = commit_pk();
    let shared_config: TTSharedConfig<B> = TTSharedConfig::with_defaults(ctx);
    let config = TTDataOwnerConfig::default()
        .with_ranks(white_box)
        .with_side_columns(white_box);
    let data_owner = TTDataOwner::new(config, shared_config, snark_pk);
    // The size is the verifier's oracle: the bins sealed under their roots.
    let serializable = block_on(data_owner.commit(&query))
        .expect("commit table to oracle")
        .seal_fingerprints();
    let mut oracle_bytes = Vec::new();
    serializable
        .serialize_compressed(&mut oracle_bytes)
        .expect("serialize oracle content");
    log_commit_size_once(case.name, white_box, oracle_bytes.len());
    oracle_bytes.len()
}

#[divan::bench(args = TPCH_TABLES, max_time = 2)]
fn bench_tpch_commit_content(bencher: Bencher, case: CommitCase) {
    commit_pk();
    bencher.bench_local(|| {
        divan::black_box(commit_content_len(case, false));
    });
    emit_benchmark_stats_row("bench_tpch_commit_content", case.name);
}

#[divan::bench(args = TPCH_TABLES, max_time = 2)]
fn bench_tpch_commit_content_tt_2(bencher: Bencher, case: CommitCase) {
    commit_pk();
    bencher.bench_local(|| {
        divan::black_box(commit_content_len(case, true));
    });
    emit_benchmark_stats_row("bench_tpch_commit_content_tt_2", case.name);
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    static RT: OnceLock<Runtime> = OnceLock::new();
    let rt = RT.get_or_init(|| Runtime::new().expect("build tokio runtime"));
    rt.block_on(future)
}

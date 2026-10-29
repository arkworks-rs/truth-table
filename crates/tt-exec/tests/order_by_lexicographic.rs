#![cfg(feature = "test-utils")]
//! ORDER BY in the lexicographic string order: string keys are proved on
//! their characters (TruthTable++ String Sort Check, §7.2, PIOP 11). The order is
//! process-wide, so every test of this binary sets it, and the sort forgery
//! is too: the forgery tests hold [`PROVING`] exclusively, the others share
//! it.
//!
//! The tests hold a `std` lock across awaits: each runs on its own
//! current-thread runtime, so blocking on the lock blocks only that test.
#![allow(clippy::await_holding_lock)]

use std::{
    path::{Path, PathBuf},
    sync::{Once, PoisonError, RwLock, RwLockReadGuard},
};

use datafusion::arrow::{
    array::UInt32Array,
    compute::{SortColumn, SortOptions, lexsort_to_indices, take_record_batch},
    record_batch::RecordBatch,
};
use datafusion::logical_expr::LogicalPlan;
use datafusion::prelude::ParquetReadOptions;
use front_end::{
    shared::TTSharedConfig,
    structs::{Artifact, TTProof},
};
use proof_planner::data_dependent_lp_optimizer::{OptimizationHint, OptimizationHints};
use tt_core::irs::string_order::{StringOrder, set_string_order};
use tt_core::test_utils::dishonest_prover::{SortForgery, set_claimed_result, set_sort_forgery};
use tt_exec::{
    backend::BenchBackend,
    paths::workspace_artifacts_dir,
    prove::{ProveBuilder, ProveOutputs},
    setup::DEFAULT_TEST_LOG_SIZE,
    test_utils::{
        prove_and_verify_query, read_result, resolve_key_paths, resolve_oracle_path,
        resolve_parquet_path, verify_on_thread,
    },
};

static MODE: Once = Once::new();
static PROVING: RwLock<()> = RwLock::new(());

fn honest() -> RwLockReadGuard<'static, ()> {
    MODE.call_once(|| set_string_order(StringOrder::Lexicographic));
    PROVING.read().unwrap_or_else(PoisonError::into_inner)
}

macro_rules! lexicographic_tests {
    ($tables:expr => [$($name:ident => $sql:expr),+ $(,)?]) => {
        $(
            #[tokio::test]
            async fn $name() {
                let _proving = honest();
                prove_and_verify_query($sql, $tables, None)
                    .await
                    .expect(concat!("end-to-end: ", $sql));
            }
        )+
    };
}

lexicographic_tests!(&["nation"] => [
    order_by_string => r#"SELECT n_name FROM nation ORDER BY n_name"#,
    order_by_string_desc => r#"SELECT n_name FROM nation ORDER BY n_name DESC"#,
    order_by_integer_then_string => r#"SELECT n_regionkey, n_name FROM nation ORDER BY n_regionkey, n_name"#,
    order_by_string_then_integer => r#"SELECT n_name, n_nationkey FROM nation ORDER BY n_name, n_nationkey"#,
    order_by_string_over_filter => r#"SELECT n_name, n_nationkey FROM nation WHERE n_regionkey = 1 ORDER BY n_name DESC"#,
    order_by_string_with_limit => r#"SELECT n_name FROM nation ORDER BY n_name LIMIT 3"#,
    order_by_string_with_like_on_it => r#"SELECT n_name FROM nation WHERE n_name LIKE '%AN%' ORDER BY n_name"#,
    order_by_string_through_aliases => r#"SELECT x.nm FROM (SELECT n_name AS nm FROM nation WHERE n_regionkey = 3) x ORDER BY x.nm DESC"#,
]);

// Five market segments over a nation's customers: tied strings hand their
// pairs to the next key.
lexicographic_tests!(&["customer"] => [
    order_by_tied_strings_then_integer => r#"SELECT c_mktsegment, c_custkey FROM customer WHERE c_nationkey = 1 ORDER BY c_mktsegment, c_custkey DESC"#,
]);

async fn assert_not_supported(query: &str, tables: &[&str], expected: &str) {
    let _proving = honest();
    let error = prove_and_verify_query(query, tables, None)
        .await
        .expect_err("the query must be rejected");
    assert!(format!("{error:#}").contains(expected), "{error:#}");
}

const KEY_PATH: &str =
    "in the lexicographic string order, a string ORDER BY key must be read from its table scan";

#[tokio::test]
async fn a_string_key_through_an_aggregate_is_not_supported() {
    assert_not_supported(
        "SELECT n_name, COUNT(*) AS c FROM nation GROUP BY n_name ORDER BY n_name",
        &["nation"],
        KEY_PATH,
    )
    .await;
}

#[tokio::test]
async fn a_string_key_through_a_join_is_not_supported() {
    assert_not_supported(
        "SELECT n.n_name, r.r_name FROM nation n JOIN region r ON n.n_regionkey = r.r_regionkey ORDER BY n.n_name",
        &["nation", "region"],
        KEY_PATH,
    )
    .await;
}

/// Five nations with distinct names, so the reversed order is the
/// descending one.
const QUERY: &str = "SELECT n_name, n_nationkey FROM nation WHERE n_regionkey = 1 ORDER BY n_name";

struct Paths {
    table: &'static str,
    pk: PathBuf,
    vk: PathBuf,
    oracle: PathBuf,
}

async fn paths(table: &'static str) -> Paths {
    let (pk, vk) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("keys");
    let parquet = resolve_parquet_path(table).expect("parquet");
    let oracle = resolve_oracle_path(&parquet, &pk).await.expect("oracle");
    Paths {
        table,
        pk,
        vk,
        oracle,
    }
}

async fn prove(paths: &Paths, query: &str, tag: &str) -> ProveOutputs {
    ProveBuilder::new()
        .with_query(query.to_owned())
        .with_parquet_paths(vec![resolve_parquet_path(paths.table).expect("parquet")])
        .with_oracle_paths(vec![paths.oracle.clone()])
        .with_pk_path(paths.pk.clone())
        .with_output_path(Some(workspace_artifacts_dir().join(format!(
            "order_by_lexicographic.{tag}.{}.pi",
            std::process::id()
        ))))
        .build()
        .expect("prove builder")
        .run()
        .await
        .expect("the prover runs")
}

/// The prover claims `claimed` of its honest result and sorts its ORDER BY
/// output by `forgery`, which must give the same rows in the same order, so
/// the result check passes and only the String Sort Check can reject, in a
/// cryptographic check rather than a panic.
async fn assert_forgery_rejected(
    table: &'static str,
    query: &str,
    forgery: SortForgery,
    claimed: impl Fn(&RecordBatch) -> RecordBatch,
) {
    MODE.call_once(|| set_string_order(StringOrder::Lexicographic));
    let _proving = PROVING.write().unwrap_or_else(PoisonError::into_inner);
    let paths = paths(table).await;
    let honest = prove(&paths, query, "honest").await;
    verify_on_thread(
        query,
        vec![paths.oracle.clone()],
        &honest.proof_path,
        &honest.result_path,
        &paths.vk,
    )
    .expect("the honest proof must verify; otherwise the rejection below proves nothing");
    let result = read_result(&honest.result_path);
    let claimed = claimed(&result);
    assert_ne!(
        claimed, result,
        "the forged order must differ from the honest one"
    );

    let forged = {
        let _forgery = set_sort_forgery(forgery);
        let _claimed = set_claimed_result(Box::new(move |_| vec![claimed.clone()]));
        prove(&paths, query, "forged").await
    };
    let reason = verify_on_thread(
        query,
        vec![paths.oracle.clone()],
        &forged.proof_path,
        &forged.result_path,
        &paths.vk,
    )
    .expect_err("a wrongly ordered result must be rejected");
    assert!(
        reason.contains("verifier cryptographic verification failed")
            && !reason.contains("panicked"),
        "{reason}"
    );
}

/// `batch` sorted on `keys`, `(column, ascending)`, in byte order for
/// strings.
fn sorted_on(batch: &RecordBatch, keys: &[(usize, bool)]) -> RecordBatch {
    let columns: Vec<SortColumn> = keys
        .iter()
        .map(|&(column, ascending)| SortColumn {
            values: batch.column(column).clone(),
            options: Some(SortOptions {
                descending: !ascending,
                nulls_first: false,
            }),
        })
        .collect();
    take_record_batch(batch, &lexsort_to_indices(&columns, None).unwrap()).unwrap()
}

#[tokio::test]
#[cfg_attr(
    feature = "honest-prover",
    ignore = "the honest prover refuses to prove a forgery"
)]
async fn a_wrongly_ordered_string_result_is_rejected() {
    assert_forgery_rejected("nation", QUERY, SortForgery::ReverseOutput, |result| {
        assert_eq!(result.num_rows(), 5);
        let reversed = UInt32Array::from((0..5).rev().collect::<Vec<u32>>());
        take_record_batch(result, &reversed).unwrap()
    })
    .await;
}

/// The segments stay in order and the customers inside each are ascending:
/// only the integer key, checked on the pairs the strings tie (PIOP 10's
/// `same`), can reject.
#[tokio::test]
#[cfg_attr(
    feature = "honest-prover",
    ignore = "the honest prover refuses to prove a forgery"
)]
async fn a_wrong_order_inside_tied_strings_is_rejected() {
    assert_forgery_rejected(
        "customer",
        "SELECT c_mktsegment, c_custkey FROM customer WHERE c_nationkey = 1 ORDER BY c_mktsegment, c_custkey DESC",
        SortForgery::ReverseLastKey,
        |result| sorted_on(result, &[(0, true), (1, true)]),
    )
    .await;
}

/// The regions stay in order and the names inside each are descending: only
/// the string key, checked on the pairs the integers tie (PIOP 27's `t_m`),
/// can reject.
#[tokio::test]
#[cfg_attr(
    feature = "honest-prover",
    ignore = "the honest prover refuses to prove a forgery"
)]
async fn a_wrong_string_order_inside_tied_integers_is_rejected() {
    assert_forgery_rejected(
        "nation",
        "SELECT n_regionkey, n_name FROM nation ORDER BY n_regionkey, n_name",
        SortForgery::ReverseLastKey,
        |result| sorted_on(result, &[(0, true), (1, false)]),
    )
    .await;
}

/// The path to the first Filter of `plan`, as an optimization hint names it.
fn filter_path(plan: &LogicalPlan) -> Option<Vec<usize>> {
    if matches!(plan, LogicalPlan::Filter(_)) {
        return Some(Vec::new());
    }
    plan.inputs()
        .into_iter()
        .enumerate()
        .find_map(|(index, input)| {
            let mut path = filter_path(input)?;
            path.insert(0, index);
            Some(path)
        })
}

/// `proof_path` with its hints and string order replaced, saved next to it.
fn rewritten(
    proof_path: &Path,
    tag: &str,
    hints: OptimizationHints,
    string_order: StringOrder,
) -> PathBuf {
    let proof = TTProof::<BenchBackend>::load(proof_path).expect("load proof");
    let openings = proof.fingerprint_openings().clone();
    let (snark_proof, _) = proof.into_parts();
    let forged = TTProof::new(snark_proof, hints, string_order, openings).expect("proof");
    let path = proof_path.with_extension(format!("{tag}.pi"));
    forged.save(&path).expect("save proof");
    path
}

/// The verifier rejects, with its reason, a proof that compacts the sorted
/// rows, whose characters nothing would bind, and a proof recorded in the
/// rank order.
#[tokio::test]
async fn a_compaction_hint_or_another_string_order_is_rejected() {
    let _proving = honest();
    let paths = paths("nation").await;
    let honest = prove(&paths, QUERY, "plan").await;

    let ctx = tt_core::session::session_context();
    let nation = resolve_parquet_path("nation").expect("nation parquet");
    ctx.register_parquet(
        "nation",
        nation.to_str().unwrap(),
        ParquetReadOptions::default(),
    )
    .await
    .expect("register nation");
    let shared = TTSharedConfig::<BenchBackend>::with_defaults(ctx);
    let lp = shared.query_to_lp(QUERY).await;
    let lp = shared.optimize_lp(shared.analyze_lp(lp).await).await;
    let target_path = filter_path(&lp).expect("the query has a filter");

    let compacted = rewritten(
        &honest.proof_path,
        "compacted",
        OptimizationHints {
            hints: vec![OptimizationHint::Compaction { target_path }],
        },
        StringOrder::Lexicographic,
    );
    let reason = verify_on_thread(
        QUERY,
        vec![paths.oracle.clone()],
        &compacted,
        &honest.result_path,
        &paths.vk,
    )
    .expect_err("a compaction under a lexicographic ORDER BY must be rejected");
    assert!(
        reason.contains("the lexicographic string order does not support compaction"),
        "{reason}"
    );

    let ranked = rewritten(
        &honest.proof_path,
        "ranked",
        OptimizationHints::default(),
        StringOrder::Rank,
    );
    let reason = verify_on_thread(
        QUERY,
        vec![paths.oracle.clone()],
        &ranked,
        &honest.result_path,
        &paths.vk,
    )
    .expect_err("a proof in another string order must be rejected");
    assert!(
        reason
            .contains("the proof orders strings in Rank mode, the verifier in Lexicographic mode"),
        "{reason}"
    );
}

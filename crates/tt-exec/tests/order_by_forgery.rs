#![cfg(feature = "test-utils")]
//! A dishonest prover against a string ORDER BY. Each forgery sorts the
//! prover's Sort output in the wrong direction ([`SortForgery`]), and the
//! prover claims that order, so the result check passes and only the
//! checks on the sort and its ranks can reject:
//! - with the sort check's witnesses left honest, they do not fit the
//!   output's ranks;
//! - with the witnesses forged to match the output, the sorted ranks
//!   decrease;
//! - with every rank above the table scans reversed to match the output,
//!   the sort is consistent, and only the binding of the ranks to the
//!   owner's can reject. Each query puts a different operator first above
//!   the scans to commit the ranks: the sort, a compaction, an aggregate, a
//!   PK-FK join's PK side and a many-to-many join.
//!
//! Every query sorts on a key with distinct values, so the reversed result
//! is the one sorted against the key's direction.
//!
//! A rejection must come from a failed check, not from a verifier panic or
//! an error before verification.
//!
//! The forgery is process-wide, so this binary has a single test.

use std::path::{Path, PathBuf};

use datafusion::arrow::{
    array::UInt32Array, compute::take_record_batch, record_batch::RecordBatch,
};
use tt_core::test_utils::dishonest_prover::{SortForgery, set_claimed_result, set_sort_forgery};
use tt_exec::{
    paths::workspace_artifacts_dir,
    prove::{ProveBuilder, ProveOutputs},
    setup::DEFAULT_TEST_LOG_SIZE,
    test_utils::{
        read_result, resolve_key_paths, resolve_oracle_path, resolve_parquet_path, verify_on_thread,
    },
};

const QUERIES: [(&str, &[SortForgery]); 5] = [
    (
        "SELECT n_name, n_nationkey FROM nation ORDER BY n_name",
        &[SortForgery::ReverseOutputAndRanks],
    ),
    (
        "SELECT n_name, n_nationkey FROM nation WHERE n_regionkey = 1 ORDER BY n_name",
        &[
            SortForgery::ReverseOutput,
            SortForgery::ReverseOutputAndWitnesses,
            SortForgery::ReverseOutputAndRanks,
        ],
    ),
    (
        "SELECT n_name, COUNT(*) AS c FROM nation GROUP BY n_name ORDER BY n_name",
        &[SortForgery::ReverseOutputAndRanks],
    ),
    (
        "SELECT r_name, n_nationkey FROM nation JOIN region ON n_regionkey = r_regionkey \
         WHERE n_nationkey < 2 ORDER BY r_name",
        &[SortForgery::ReverseOutputAndRanks],
    ),
    (
        "SELECT a.n_name, b.n_nationkey FROM nation a JOIN nation b ON a.n_regionkey = b.n_regionkey \
         WHERE b.n_nationkey = 0 ORDER BY a.n_name",
        &[SortForgery::ReverseOutputAndRanks],
    ),
];

const TABLES: [&str; 2] = ["nation", "region"];

async fn prove(query: &str, pk: &Path, oracles: &[PathBuf], tag: &str) -> ProveOutputs {
    ProveBuilder::new()
        .with_query(query.to_owned())
        .with_parquet_paths(
            TABLES
                .iter()
                .map(|table| resolve_parquet_path(table).expect("test parquet"))
                .collect(),
        )
        .with_oracle_paths(oracles.to_vec())
        .with_pk_path(pk.to_path_buf())
        .with_output_path(Some(
            workspace_artifacts_dir()
                .join(format!("order_by_forgery.{tag}.{}.pi", std::process::id())),
        ))
        .build()
        .expect("prove builder")
        .run()
        .await
        .expect("the prover runs")
}

fn reversed(batch: &RecordBatch) -> RecordBatch {
    let rows = batch.num_rows() as u32;
    let indices = UInt32Array::from((0..rows).rev().collect::<Vec<_>>());
    take_record_batch(batch, &indices).unwrap()
}

#[tokio::test]
#[cfg_attr(
    feature = "honest-prover",
    ignore = "the honest prover refuses to prove a forgery"
)]
async fn wrongly_ordered_string_results_are_rejected() {
    let (pk, vk) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("keys");
    let mut oracles = Vec::new();
    for table in TABLES {
        let parquet = resolve_parquet_path(table).expect("test parquet");
        oracles.push(
            resolve_oracle_path(&parquet, &pk)
                .await
                .expect("test oracle"),
        );
    }

    let mut wrongly_handled = Vec::new();
    for (index, (query, forgeries)) in QUERIES.iter().enumerate() {
        let honest = prove(query, &pk, &oracles, &format!("{index}.honest")).await;
        verify_on_thread(
            query,
            oracles.clone(),
            &honest.proof_path,
            &honest.result_path,
            &vk,
        )
        .expect("the honest proof must verify; otherwise the rejections below prove nothing");
        let claimed = reversed(&read_result(&honest.result_path));
        assert!(claimed.num_rows() > 1, "{query} sorts too few rows");

        for &forgery in *forgeries {
            let claimed = claimed.clone();
            let forged = {
                let _forgery = set_sort_forgery(forgery);
                let _claimed = set_claimed_result(Box::new(move |_| vec![claimed.clone()]));
                prove(query, &pk, &oracles, &format!("{index}.{forgery:?}")).await
            };
            match verify_on_thread(
                query,
                oracles.clone(),
                &forged.proof_path,
                &forged.result_path,
                &vk,
            ) {
                Ok(()) => wrongly_handled.push(format!("{query}: {forgery:?} verified")),
                Err(reason)
                    if reason.contains("verifier cryptographic verification failed")
                        && !reason.contains("panicked") =>
                {
                    eprintln!("rejected {forgery:?} on {query}: {reason}")
                }
                Err(reason) => wrongly_handled.push(format!(
                    "{query}: {forgery:?} failed for another reason: {reason}"
                )),
            }
        }
    }
    assert!(wrongly_handled.is_empty(), "{wrongly_handled:#?}");
}

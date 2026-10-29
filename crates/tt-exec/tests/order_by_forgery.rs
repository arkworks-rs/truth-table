#![cfg(feature = "test-utils")]
//! A dishonest prover against a string ORDER BY. Each forgery sorts the
//! prover's Sort output in the wrong direction ([`SortForgery`]), and the
//! prover claims that order, so the result check passes and only the sort's
//! checks can reject:
//! - with the sort check's witnesses left honest, the sorted ranks are not
//!   the ranks of the output's strings, which the rank lookup rejects in the
//!   keyed sums;
//! - with the witnesses forged to match the output, the sorted ranks
//!   decrease, which the sort check rejects.
//!
//! A rejection must come from a failed check, not from a verifier panic or
//! an error before verification.
//!
//! The forgery is process-wide, so this binary has a single test.

use std::path::Path;

use ark_piop::types::LookupProtocol;
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

/// Five nations with distinct names, so the reversed order is the
/// descending one.
const QUERY: &str = "SELECT n_name, n_nationkey FROM nation WHERE n_regionkey = 1 ORDER BY n_name";

async fn prove(pk: &Path, oracle: &Path, tag: &str) -> ProveOutputs {
    ProveBuilder::new()
        .with_query(QUERY.to_owned())
        .with_parquet_paths(vec![
            resolve_parquet_path("nation").expect("nation parquet"),
        ])
        .with_oracle_paths(vec![oracle.to_path_buf()])
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
    let nation = resolve_parquet_path("nation").expect("nation parquet");
    let oracle = resolve_oracle_path(&nation, &pk)
        .await
        .expect("nation oracle");

    let honest = prove(&pk, &oracle, "honest").await;
    verify_on_thread(
        QUERY,
        vec![oracle.clone()],
        &honest.proof_path,
        &honest.result_path,
        &vk,
    )
    .expect("the honest proof must verify; otherwise the rejections below prove nothing");
    let claimed = reversed(&read_result(&honest.result_path));
    assert_eq!(claimed.num_rows(), 5);

    let keyed_sums_differ = match LookupProtocol::from_env()
        .expect("lookup protocol")
        .unwrap_or_default()
    {
        LookupProtocol::LogUpGkr => "the two sides of the keyed sums have different sums",
        LookupProtocol::LogUp => "the two sides of keyed sum",
    };
    let mut wrongly_handled = Vec::new();
    for (forgery, expected) in [
        (SortForgery::ReverseOutput, Some(keyed_sums_differ)),
        (SortForgery::ReverseOutputAndWitnesses, None),
    ] {
        let claimed = claimed.clone();
        let forged = {
            let _forgery = set_sort_forgery(forgery);
            let _claimed = set_claimed_result(Box::new(move |_| vec![claimed.clone()]));
            prove(&pk, &oracle, &format!("{forgery:?}")).await
        };
        match verify_on_thread(
            QUERY,
            vec![oracle.clone()],
            &forged.proof_path,
            &forged.result_path,
            &vk,
        ) {
            Ok(()) => wrongly_handled.push(format!("{forgery:?} verified")),
            Err(reason)
                if reason.contains("verifier cryptographic verification failed")
                    && !reason.contains("panicked")
                    && expected.is_none_or(|expected| reason.contains(expected)) =>
            {
                eprintln!("rejected {forgery:?}: {reason}")
            }
            Err(reason) => {
                wrongly_handled.push(format!("{forgery:?} failed for another reason: {reason}"))
            }
        }
    }
    assert!(wrongly_handled.is_empty(), "{wrongly_handled:#?}");
}

#![cfg(feature = "test-utils")]
//! A dishonest prover that outputs every group of a GROUP BY twice, gives
//! each copy a nonzero share of the group's lookup multiplicity
//! ([`set_duplicate_groups_forgery`]), and claims the doubled result, so only
//! the NoDupcheck inside the aggregate's Suppcheck can reject. Each query
//! groups by columns that hold no unique key of the aggregate's input, so
//! that check must run: a prefix of a composite primary key, the primary key
//! of a join side whose rows the join repeats, and that key with a column it
//! fixes, which the check then compares on the key alone. Every group has at
//! least two input rows, so every group is doubled.
//!
//! The forgery is process-wide, so this binary has a single test.

use std::path::{Path, PathBuf};

use datafusion::arrow::compute::concat_batches;
use tt_core::test_utils::dishonest_prover::{set_claimed_result, set_duplicate_groups_forgery};
use tt_exec::{
    paths::workspace_artifacts_dir,
    prove::{ProveBuilder, ProveOutputs},
    setup::DEFAULT_TEST_LOG_SIZE,
    test_utils::{
        read_result, resolve_key_paths, resolve_oracle_path, resolve_parquet_path, verify_on_thread,
    },
};

const QUERIES: &[(&str, &[&str])] = &[
    (
        "SELECT ps_partkey FROM partsupp GROUP BY ps_partkey",
        &["partsupp"],
    ),
    (
        "SELECT r_regionkey FROM region JOIN nation ON r_regionkey = n_regionkey \
         GROUP BY r_regionkey",
        &["region", "nation"],
    ),
    (
        "SELECT r_regionkey, r_name FROM region JOIN nation ON r_regionkey = n_regionkey \
         GROUP BY r_regionkey, r_name",
        &["region", "nation"],
    ),
];

async fn prove(
    query: &str,
    tables: &[&str],
    pk: &Path,
    oracles: &[PathBuf],
    tag: &str,
) -> ProveOutputs {
    ProveBuilder::new()
        .with_query(query.to_owned())
        .with_parquet_paths(
            tables
                .iter()
                .map(|table| resolve_parquet_path(table).expect("parquet"))
                .collect(),
        )
        .with_oracle_paths(oracles.to_vec())
        .with_pk_path(pk.to_path_buf())
        // Compaction sizes its domain from the honest row count, which the
        // doubled groups exceed; without it the NoDupcheck is the only check
        // left to reject.
        .with_data_dependent_rules(Vec::new())
        .with_output_path(Some(
            workspace_artifacts_dir()
                .join(format!("group_by_forgery.{tag}.{}.pi", std::process::id())),
        ))
        .build()
        .expect("prove builder")
        .run()
        .await
        .expect("the prover runs")
}

#[tokio::test]
#[cfg_attr(
    feature = "honest-prover",
    ignore = "the honest prover refuses to prove a forgery"
)]
async fn duplicated_groups_are_rejected() {
    let (pk, vk) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("keys");
    for (index, (query, tables)) in QUERIES.iter().enumerate() {
        let mut oracles = Vec::new();
        for table in *tables {
            let parquet = resolve_parquet_path(table).expect("parquet");
            oracles.push(resolve_oracle_path(&parquet, &pk).await.expect("oracle"));
        }

        let honest = prove(query, tables, &pk, &oracles, &format!("honest{index}")).await;
        verify_on_thread(
            query,
            oracles.clone(),
            &honest.proof_path,
            &honest.result_path,
            &vk,
        )
        .expect("the honest proof must verify; otherwise the rejection below proves nothing");
        let result = read_result(&honest.result_path);
        let doubled = concat_batches(&result.schema(), &[result.clone(), result]).unwrap();

        let forged = {
            let _forgery = set_duplicate_groups_forgery();
            let _claimed = set_claimed_result(Box::new(move |_| vec![doubled.clone()]));
            prove(query, tables, &pk, &oracles, &format!("forged{index}")).await
        };
        let verdict = verify_on_thread(
            query,
            oracles.clone(),
            &forged.proof_path,
            &forged.result_path,
            &vk,
        );
        match verdict {
            Err(reason)
                if reason.contains("verifier cryptographic verification failed")
                    && !reason.contains("panicked") => {}
            other => panic!("duplicated groups must fail a check on {query}, got {other:?}"),
        }
    }
}

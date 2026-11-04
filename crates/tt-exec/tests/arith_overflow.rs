#![cfg(feature = "test-utils")]
//! Int64 products past their type, in `x - x = 0`, which holds both under
//! DataFusion's wrapping arithmetic and in the field whatever `x` is. Past
//! its type but within the field, `x` is still the right integer and the
//! proof verifies; past the field it would wrap, so a range check has to
//! reject it.

use tt_exec::{
    paths::workspace_artifacts_dir,
    prove::ProveBuilder,
    setup::DEFAULT_TEST_LOG_SIZE,
    test_utils::{resolve_key_paths, resolve_oracle_path, resolve_parquet_path, verify_on_thread},
};

async fn verdict(query: &str, tag: &str) -> Result<(), String> {
    let (pk, vk) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("keys");
    let nation = resolve_parquet_path("nation").expect("nation parquet");
    let oracle = resolve_oracle_path(&nation, &pk)
        .await
        .expect("nation oracle");
    let outputs = ProveBuilder::new()
        .with_query(query.to_owned())
        .with_parquet_paths(vec![nation])
        .with_oracle_paths(vec![oracle.clone()])
        .with_pk_path(pk.clone())
        .with_output_path(Some(
            workspace_artifacts_dir()
                .join(format!("arith_overflow.{tag}.{}.pi", std::process::id())),
        ))
        .build()
        .expect("prove builder")
        .run()
        .await
        .map_err(|e| format!("the prover refused: {e}"))?;
    verify_on_thread(
        query,
        vec![oracle],
        &outputs.proof_path,
        &outputs.result_path,
        &vk,
    )
}

#[tokio::test]
async fn product_within_its_type_verifies() {
    verdict(
        "SELECT n_name FROM nation WHERE n_nationkey * 1024 - n_nationkey * 1024 = 0",
        "within",
    )
    .await
    .expect("a product within Int64 must verify; otherwise the rejection below proves nothing");
}

/// `k·2^62` passes Int64 but stays far below the field: no check needed.
#[tokio::test]
async fn a_product_past_its_type_verifies() {
    verdict(
        "SELECT n_name FROM nation \
         WHERE n_nationkey * 4611686018427387904 - n_nationkey * 4611686018427387904 = 0",
        "past_type",
    )
    .await
    .expect("a product past Int64 but within the field must verify");
}

/// `k·2^310` would pass the field, so `k·2^124` is range-checked on the way
/// and fails Int64.
#[tokio::test]
async fn a_product_past_the_field_is_rejected() {
    let x = "n_nationkey * 4611686018427387904 * 4611686018427387904 * 4611686018427387904 \
             * 4611686018427387904 * 4611686018427387904";
    let verdict = verdict(
        &format!("SELECT n_name FROM nation WHERE {x} - {x} = 0"),
        "past_field",
    )
    .await;
    assert_rejected(verdict);
}

fn assert_rejected(verdict: Result<(), String>) {
    match verdict {
        Err(reason)
            if cfg!(feature = "honest-prover") && reason.starts_with("the prover refused") => {}
        Err(reason)
            if reason.contains("verifier cryptographic verification failed")
                && !reason.contains("panicked") => {}
        other => panic!("a value past the field must fail a range check, got {other:?}"),
    }
}

#![cfg(feature = "test-utils")]

//! LIKE on the bench-data `lineitem` (2^20 rows) with the bench-size key, in
//! a process of its own: fingerprint rules are per process and keyed by
//! column name, and the bench-data and test-data `lineitem` give `l_comment`
//! different rules.

#[tokio::test]
async fn bench_like_infix_lineitem() {
    tt_exec::test_utils::prove_and_verify_query_bench(
        r#"SELECT l_returnflag FROM lineitem WHERE l_comment LIKE '%green%'"#,
        &["lineitem"],
        None,
    )
    .await
    .expect("bench-data lineitem LIKE end-to-end");
}

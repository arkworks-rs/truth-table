#![cfg(feature = "test-utils")]

async fn assert_refused(query: &str, tables: &[&str]) {
    let error = tt_exec::test_utils::prove_and_verify_query(query, tables, None)
        .await
        .expect_err("the proof has no check for a scalar function");
    assert!(
        format!("{error:#}").contains("scalar functions are not supported"),
        "{error:#}"
    );
}

#[tokio::test]
async fn scalar_functions_are_not_supported() {
    for (query, tables) in [
        (
            "SELECT abs(s_acctbal) AS a FROM supplier",
            &["supplier"][..],
        ),
        (
            "SELECT n_nationkey FROM nation WHERE greatest(n_nationkey, n_regionkey) > 10",
            &["nation"],
        ),
        (
            "SELECT o_orderkey FROM orders WHERE date_part('year', o_orderdate) = 1995",
            &["orders"],
        ),
    ] {
        assert_refused(query, tables).await;
    }
}

#![cfg(feature = "test-utils")]

mod support;

end_to_end_tests!(&["nation"] => [
    cast_to_a_wider_integer => "SELECT n_nationkey, CAST(n_regionkey AS DECIMAL(20, 0)) AS c FROM nation",
    cast_to_a_narrower_integer => "SELECT n_nationkey, CAST(n_regionkey AS INT) AS c FROM nation",
    cast_to_a_larger_scale => "SELECT n_nationkey, CAST(n_regionkey AS DECIMAL(10, 2)) AS c FROM nation",
    cast_in_a_comparison => "SELECT n_nationkey FROM nation WHERE CAST(n_nationkey AS DECIMAL(10, 2)) > 7.5",
]);

end_to_end_tests!(&["supplier"] => [
    // `s_acctbal` has negative values and two decimal places.
    cast_to_a_smaller_scale_rounds => "SELECT s_suppkey, CAST(s_acctbal AS DECIMAL(15, 1)) AS c FROM supplier",
    cast_to_an_integer_truncates => "SELECT s_suppkey, CAST(s_acctbal AS BIGINT) AS c FROM supplier",
    cast_to_a_smaller_scale_after_a_filter => "SELECT SUM(CAST(s_acctbal AS DECIMAL(15, 0))) AS s FROM supplier WHERE s_nationkey < 5",
]);

async fn assert_cast_refused(query: &str, tables: &[&str]) {
    let error = tt_exec::test_utils::prove_and_verify_query(query, tables, None)
        .await
        .expect_err("the proof has no check for this cast");
    assert!(
        format!("{error:#}").contains("CAST is supported between integers and decimals"),
        "{error:#}"
    );
}

#[tokio::test]
async fn cast_to_a_string_is_not_supported() {
    assert_cast_refused(
        "SELECT CAST(n_nationkey AS VARCHAR) AS c FROM nation",
        &["nation"],
    )
    .await;
}

#[tokio::test]
async fn cast_to_a_float_is_not_supported() {
    assert_cast_refused(
        "SELECT CAST(s_acctbal AS DOUBLE) AS c FROM supplier",
        &["supplier"],
    )
    .await;
}

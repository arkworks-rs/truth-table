#![cfg(feature = "test-utils")]

mod support;

// A BETWEEN over up to three values becomes an IN list, which the optimizer
// splits into equalities; a longer one, the comparisons that prove it.
end_to_end_tests!(&["nation"] => [
    between_in_a_filter => "SELECT n_nationkey FROM nation WHERE n_regionkey BETWEEN 1 AND 3",
    between_of_four_values => "SELECT n_nationkey FROM nation WHERE n_regionkey BETWEEN 0 AND 3",
    not_between_in_a_filter => "SELECT n_nationkey FROM nation WHERE n_nationkey NOT BETWEEN 5 AND 20",
    not_between_of_two_values => "SELECT n_nationkey FROM nation WHERE n_regionkey NOT BETWEEN 1 AND 2",
]);

end_to_end_tests!(&["lineitem"] => [
    decimal_between_of_three_values => "SELECT l_orderkey FROM lineitem WHERE l_discount BETWEEN 0.05 AND 0.07",
]);

end_to_end_tests!(&["orders"] => [
    date_between_of_three_days => "SELECT o_orderkey FROM orders WHERE o_orderdate BETWEEN CAST('1995-01-01' AS date) AND CAST('1995-01-03' AS date)",
]);

#[tokio::test]
async fn between_strings_is_not_supported() {
    let error = tt_exec::test_utils::prove_and_verify_query(
        "SELECT n_nationkey FROM nation WHERE n_name BETWEEN 'B' AND 'F'",
        &["nation"],
        None,
    )
    .await
    .expect_err("comparing strings has no check");
    assert!(
        format!("{error:#}").contains("comparing strings"),
        "{error:#}"
    );
}

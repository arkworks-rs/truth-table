#![cfg(feature = "test-utils")]

mod support;

end_to_end_tests!(&["nation"] => [
    case_in_a_projection => "SELECT n_nationkey, CASE WHEN n_regionkey < 2 THEN 1 ELSE 0 END AS c FROM nation",
    case_with_several_conditions => "SELECT n_nationkey, CASE WHEN n_regionkey < 2 THEN n_nationkey WHEN n_regionkey < 4 THEN 2 * n_nationkey ELSE 7 END AS c FROM nation",
    simple_case => "SELECT n_nationkey, CASE n_regionkey WHEN 0 THEN 10 WHEN 3 THEN 30 ELSE 0 END AS c FROM nation",
    nested_case => "SELECT n_nationkey, CASE WHEN n_regionkey < 3 THEN CASE WHEN n_nationkey < 10 THEN 1 ELSE 2 END ELSE 3 END AS c FROM nation",
    case_in_a_filter => "SELECT n_nationkey FROM nation WHERE CASE WHEN n_regionkey < 2 THEN n_nationkey ELSE 0 END > 3",
]);

end_to_end_tests!(&["supplier"] => [
    decimal_case_in_a_sum => "SELECT SUM(CASE WHEN s_nationkey < 10 THEN s_acctbal ELSE 0 END) AS s FROM supplier",
]);

// Rows a filter drops keep their data, and every row meets the condition: an
// inactive row's CASE value must not count in the SUM.
end_to_end_tests!(&["nation", "region"] => [
    case_in_a_sum_over_a_filter => "SELECT SUM(CASE WHEN n_nationkey >= 0 THEN n_nationkey ELSE 0 END) AS s FROM nation WHERE n_regionkey < 2",
    case_in_a_sum_over_a_filtered_join => "SELECT SUM(CASE WHEN n_nationkey >= 0 THEN n_nationkey ELSE 0 END) AS s FROM nation JOIN region ON n_regionkey = r_regionkey WHERE r_name <> 'ASIA'",
]);

#[tokio::test]
async fn case_with_string_results_is_not_supported() {
    let error = tt_exec::test_utils::prove_and_verify_query(
        "SELECT CASE WHEN n_regionkey < 2 THEN n_name ELSE 'other' END AS c FROM nation",
        &["nation"],
        None,
    )
    .await
    .expect_err("a CASE with string results has no check");
    assert!(
        format!("{error:#}").contains("CASE is supported with integer and decimal results only"),
        "{error:#}"
    );
}

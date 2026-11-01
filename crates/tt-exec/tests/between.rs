#![cfg(feature = "test-utils")]

mod support;

// The optimizer rewrites BETWEEN into the comparisons that prove it.
end_to_end_tests!(&["nation"] => [
    between_in_a_filter => "SELECT n_nationkey FROM nation WHERE n_regionkey BETWEEN 1 AND 3",
    not_between_in_a_filter => "SELECT n_nationkey FROM nation WHERE n_nationkey NOT BETWEEN 5 AND 20",
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

#![cfg(feature = "test-utils")]

mod support;

end_to_end_tests!(&["lineitem"] => [
    simple_equality_filter_and => r#"SELECT l_returnflag, l_linestatus FROM lineitem WHERE l_returnflag = 'R' AND l_linestatus= 'F'"#,
    simple_equality_filter => r#"SELECT l_returnflag, l_linestatus FROM lineitem WHERE l_returnflag = 'R'"#,
    simple_inequality_filter => r#"SELECT l_returnflag, l_linestatus FROM lineitem WHERE l_shipdate < DATE '1998-09-01'"#,
]);

end_to_end_tests!(&["nation"] => [
    simple_like_infix_nation => r#"SELECT n_name FROM nation WHERE n_comment LIKE '%haggle%'"#,
    // `%slyly%` leaves more pre-filter survivors than matches, so the planner
    // compacts a second time after the LIKE (compaction + DPUC + lookup). The
    // ORDER BY keeps that compaction; this is its only verifying coverage.
    like_infix_nation_second_compaction => r#"SELECT n_name FROM nation WHERE n_comment LIKE '%slyly%' ORDER BY n_name"#,
    // The same LIKE with only a projection above it: its output stays
    // uncompacted and the result check takes the LIKE's own domain.
    like_infix_nation_uncompacted_tail => r#"SELECT n_name FROM nation WHERE n_comment LIKE '%slyly%'"#,
    // Multi-factor LIKE: factors match in order, without overlap, and a row
    // that misses a factor is out (13 rows).
    like_two_factors_nation => r#"SELECT n_name FROM nation WHERE n_comment LIKE '%the%ly%'"#,
    // No row has the first factor, so nothing matches, even rows that have
    // the second one.
    like_first_factor_absent_nation => r#"SELECT n_name FROM nation WHERE n_comment LIKE '%zqzq%the%'"#,
    // A repeated factor needs two separate occurrences (17 rows).
    like_repeated_factor_nation => r#"SELECT n_name FROM nation WHERE n_comment LIKE '%ly%ly%'"#,
    // Suffix on the last string, whose successor slot is padding.
    like_suffix_last_string_nation => r#"SELECT n_name FROM nation WHERE n_comment LIKE '%be'"#,
    like_prefix_and_suffix_nation => r#"SELECT n_name FROM nation WHERE n_comment LIKE 'y%be'"#,
]);

// Equality filter at a small scale (`part`, nv=14).
end_to_end_tests!(&["part"] => [
    equality_filter_part => r#"SELECT p_name FROM part WHERE p_brand = 'Brand#13'"#,
]);

/// Equality filter on one string column projecting another, on `orders`
/// (nv=17).
#[tokio::test]
async fn equality_filter_orders() {
    tt_exec::test_utils::prove_and_verify_query(
        r#"SELECT o_comment FROM orders WHERE o_orderstatus = 'F'"#,
        &["orders"],
        None,
    )
    .await
    .expect("end-to-end: equality_filter_orders");
}

end_to_end_tests!(&["orders"] => [
    // The pattern matches about 1 % of `o_comment`, so the pre-filter runs.
    like_infix_orders_special_requests => r#"SELECT o_orderkey FROM orders WHERE o_comment LIKE '%special%requests%'"#,
    // Enough survivors that the compaction's offset no-dup sorts a column
    // longer than one DataFusion batch; the sort's diffs must hold across the
    // batch boundary.
    like_infix_orders_final_requests => r#"SELECT o_orderkey FROM orders WHERE o_comment LIKE '%final%requests%'"#,
]);

end_to_end_tests!(&["lineitem"] => [
    simple_like_infix_lineitem => r#"SELECT l_returnflag FROM lineitem WHERE l_comment LIKE '%green%'"#,
    // Matches nothing, and the pre-filter's chosen bins keep no row either,
    // so the LIKE sees an empty input: its plan hints must still be built
    // from the padded empty table.
    like_prefilter_keeps_no_row => r#"SELECT l_returnflag FROM lineitem WHERE l_comment LIKE '%quickly%xylophone%'"#,
]);

/// LIKE on the bench-data `lineitem` (2^20 rows) with the bench-size key.
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

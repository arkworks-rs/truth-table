#![cfg(feature = "test-utils")]

mod support;

end_to_end_tests!(&["nation"] => [
    order_by_filtered_desc => r#"SELECT n_nationkey, n_name FROM nation WHERE n_regionkey = 1 ORDER BY n_nationkey DESC"#,
    order_by_two_keys => r#"SELECT n_regionkey, n_name FROM nation ORDER BY n_regionkey, n_name"#,
    order_by_with_limit => r#"SELECT n_name FROM nation ORDER BY n_name LIMIT 3"#,
    // Five nations share each region: the result must keep the proof's
    // order among tied rows.
    order_by_with_ties => r#"SELECT n_regionkey, n_nationkey FROM nation ORDER BY n_regionkey"#,
    // The LIMIT keeps two of region 3's five tied nations (#137).
    order_by_with_ties_and_limit => r#"SELECT n_regionkey, n_name FROM nation ORDER BY n_regionkey DESC LIMIT 7"#,
    order_by_filtered_with_ties_and_limit => r#"SELECT n_regionkey, n_name FROM nation WHERE n_nationkey > 2 ORDER BY n_regionkey LIMIT 6"#,
]);

// ORDER BY ... LIMIT through tied rows above a join or an aggregate, whose
// output rows the proof numbers from its inputs' row orders (#137).
end_to_end_tests!(&["nation", "region"] => [
    order_by_ties_limit_pkfk_fk_left => r#"SELECT n.n_name, r.r_name FROM nation n JOIN region r ON n.n_regionkey = r.r_regionkey ORDER BY r.r_name LIMIT 7"#,
    order_by_ties_limit_many_to_many => r#"SELECT n1.n_name AS left_name, n2.n_name AS right_name FROM nation n1 JOIN nation n2 ON n1.n_regionkey = n2.n_regionkey ORDER BY n1.n_regionkey LIMIT 12"#,
    order_by_ties_limit_group_by => r#"SELECT n_regionkey, COUNT(*) AS c FROM nation GROUP BY n_regionkey ORDER BY c LIMIT 2"#,
]);

// Rows tied on `o_orderpriority` come from many customers, so the proof's
// order (by the foreign-key side, orders) differs from (customer, order).
end_to_end_tests!(&["customer", "orders"] => [
    order_by_ties_limit_pkfk_fk_right => r#"SELECT c.c_name, o.o_orderkey FROM customer c JOIN orders o ON c.c_custkey = o.o_custkey ORDER BY o.o_orderpriority LIMIT 10"#,
    // Without a LIMIT too: ResultCheck compares an ORDER BY result in order.
    order_by_ties_above_join => r#"SELECT c.c_name, o.o_orderkey FROM customer c JOIN orders o ON c.c_custkey = o.o_custkey ORDER BY o.o_shippriority, c.c_nationkey"#,
]);

// ORDER BY … LIMIT in a subquery. A filter stays above it (it cannot be
// pushed through the LIMIT), so the nodes above see the sorted rows' order,
// and compaction must not reorder them.
end_to_end_tests!(&["nation"] => [
    ordered_limit_in_subquery => r#"SELECT n_name FROM (SELECT * FROM nation ORDER BY n_nationkey LIMIT 20) s"#,
    filter_over_ordered_limit => r#"SELECT n_name FROM (SELECT * FROM nation ORDER BY n_nationkey LIMIT 20) s WHERE n_regionkey = 1"#,
    limit_over_filter_over_ordered_limit => r#"SELECT n_name FROM (SELECT * FROM nation ORDER BY n_nationkey LIMIT 20) s WHERE n_regionkey = 1 LIMIT 2"#,
    ordered_filter_over_ordered_limit => r#"SELECT n_name, n_nationkey FROM (SELECT * FROM nation ORDER BY n_nationkey LIMIT 20) s WHERE n_regionkey = 1 ORDER BY n_nationkey DESC"#,
]);

// String keys are sorted on their base column's rank (TruthTable++ Rank-Based String Sort Check, §7.3, PIOP 13).
end_to_end_tests!(&["nation", "region"] => [
    order_by_string_desc => r#"SELECT n_name FROM nation ORDER BY n_name DESC"#,
    order_by_string_alias => r#"SELECT n_name AS nation FROM nation WHERE n_regionkey = 2 ORDER BY nation"#,
    order_by_string_through_subquery_alias => r#"SELECT x.nm FROM (SELECT n_name AS nm FROM nation WHERE n_regionkey = 3) x ORDER BY x.nm DESC"#,
    order_by_string_group_by => r#"SELECT n_name, COUNT(*) AS c FROM nation GROUP BY n_name ORDER BY n_name DESC"#,
    order_by_integer_after_string => r#"SELECT r.r_name, n.n_nationkey FROM nation n JOIN region r ON n.n_regionkey = r.r_regionkey ORDER BY r.r_name, n.n_nationkey DESC"#,
    order_by_strings_from_two_tables => r#"SELECT r.r_name, n.n_name FROM nation n JOIN region r ON n.n_regionkey = r.r_regionkey ORDER BY r.r_name DESC, n.n_name"#,
    order_by_string_fk_side => r#"SELECT n.n_name, r.r_name FROM nation n JOIN region r ON n.n_regionkey = r.r_regionkey ORDER BY n.n_name"#,
    order_by_string_pk_side => r#"SELECT n.n_nationkey, r.r_name FROM nation n JOIN region r ON n.n_regionkey = r.r_regionkey ORDER BY r.r_name, n.n_nationkey"#,
    // Two keys over same-named columns of one base column: each is bound to
    // its own position, with its own direction.
    order_by_one_base_column_twice => r#"SELECT n1.n_name AS a, n2.n_name AS b FROM nation n1 JOIN nation n2 ON n1.n_regionkey = n2.n_regionkey ORDER BY n1.n_name, n2.n_name DESC"#,
    order_by_integer_keys_bound_by_position => r#"SELECT n1.n_nationkey AS a, n2.n_nationkey AS b FROM nation n1 JOIN nation n2 ON n1.n_regionkey = n2.n_regionkey ORDER BY n1.n_nationkey, n2.n_nationkey DESC"#,
]);

async fn assert_not_supported(query: &str, tables: &[&str], expected: &str) {
    let error = tt_exec::test_utils::prove_and_verify_query(query, tables, None)
        .await
        .expect_err("the query must be rejected");
    assert!(format!("{error:#}").contains(expected), "{error:#}");
}

#[tokio::test]
async fn an_order_by_key_of_a_computed_string_is_not_supported() {
    assert_not_supported(
        "SELECT n_name FROM nation ORDER BY lower(n_name)",
        &["nation"],
        "an ORDER BY key must be a column of the sorted input",
    )
    .await;
}

#[tokio::test]
async fn a_string_order_by_key_without_a_base_column_is_not_supported() {
    assert_not_supported(
        "SELECT n_name FROM nation UNION ALL SELECT r_name FROM region ORDER BY 1",
        &["nation", "region"],
        "a string ORDER BY key must be a copy of a base-table column",
    )
    .await;
}

#[tokio::test]
async fn an_order_by_key_without_an_ordered_encoding_is_not_supported() {
    assert_not_supported(
        "SELECT CAST(n_nationkey AS DOUBLE) AS f FROM nation ORDER BY f",
        &["nation"],
        "order-preserving encoding",
    )
    .await;
}

#[tokio::test]
async fn string_comparisons_are_not_supported() {
    assert_not_supported(
        "SELECT n_name FROM nation WHERE n_name < 'C'",
        &["nation"],
        "comparing strings",
    )
    .await;
}

#[tokio::test]
async fn min_and_max_over_strings_are_not_supported() {
    assert_not_supported(
        "SELECT n_regionkey, MAX(n_name) AS m FROM nation GROUP BY n_regionkey",
        &["nation"],
        "MIN and MAX over strings",
    )
    .await;
}

#[tokio::test]
async fn greatest_and_least_over_strings_are_not_supported() {
    for query in [
        "SELECT n_name FROM nation WHERE greatest(n_name, 'M') = n_name",
        "SELECT least(n_name, 'M') AS l FROM nation",
    ] {
        assert_not_supported(
            query,
            &["nation"],
            "GREATEST and LEAST over strings are not supported",
        )
        .await;
    }
}

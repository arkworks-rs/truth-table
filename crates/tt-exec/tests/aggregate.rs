#![cfg(feature = "test-utils")]

mod support;

end_to_end_tests!(&["lineitem"] => [
    grouped_extrema => r#"SELECT
        l_orderkey,
        MAX(l_linenumber),
        MIN(l_linenumber)
    FROM lineitem
    GROUP BY l_orderkey"#,
    ungrouped_extrema => r#"SELECT
        MAX(l_linenumber),
        MIN(l_linenumber)
    FROM lineitem"#,
]);

// GROUP BY without MAX/MIN: only Distinct (Boolcheck, the output activator
// inside the input's, Suppcheck) binds the groups.
end_to_end_tests!(&["nation"] => [
    group_by_count => r#"SELECT n_regionkey, COUNT(*) FROM nation GROUP BY n_regionkey"#,
    group_by_sum => r#"SELECT n_regionkey, SUM(n_nationkey) FROM nation GROUP BY n_regionkey"#,
    group_by_string_key => r#"SELECT n_name, COUNT(*) FROM nation GROUP BY n_name"#,
    group_by_after_filter => r#"SELECT n_regionkey, COUNT(*) FROM nation WHERE n_regionkey < 4 GROUP BY n_regionkey"#,
    group_by_having => r#"SELECT n_regionkey FROM nation WHERE n_regionkey < 3 GROUP BY n_regionkey HAVING COUNT(*) > 0"#,
]);

// AVG and `/` truncate toward zero; `s_acctbal` has negative values, so both
// signs of the numerator are checked.
end_to_end_tests!(&["supplier"] => [
    grouped_avg => r#"SELECT s_nationkey, AVG(s_acctbal) FROM supplier GROUP BY s_nationkey"#,
    ungrouped_avg => r#"SELECT AVG(s_acctbal) FROM supplier"#,
    ungrouped_count => r#"SELECT COUNT(s_acctbal) FROM supplier"#,
    ungrouped_count_star => r#"SELECT COUNT(*) FROM supplier WHERE s_acctbal > 0"#,
    divide_by_negative_literal => r#"SELECT s_acctbal / CAST(-3.00 AS DECIMAL(15, 2)) FROM supplier"#,
    divide_aggregates => r#"SELECT s_nationkey, SUM(s_acctbal) / SUM(s_suppkey) AS ratio FROM supplier GROUP BY s_nationkey"#,
]);

// A materialized expression over an aggregate, with no alias to name it.
end_to_end_tests!(&["supplier"] => [
    unaliased_compare_aggregates => r#"SELECT s_nationkey, SUM(s_acctbal) > SUM(s_suppkey) FROM supplier GROUP BY s_nationkey"#,
    unaliased_divide_aggregates => r#"SELECT s_nationkey, SUM(s_acctbal) / SUM(s_suppkey) FROM supplier GROUP BY s_nationkey"#,
]);

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

mod support;

end_to_end_tests!(&["lineitem"] => [
    aggregate_count_by_1_col => r#"SELECT l_suppkey, COUNT(l_suppkey) FROM lineitem GROUP BY l_suppkey,l_orderkey"#,
    aggregate_sum_by_1_col => r#"SELECT l_suppkey, SUM(l_suppkey) FROM lineitem GROUP BY l_suppkey,l_orderkey"#,
    aggregate_max_by_1_col => r#"SELECT l_suppkey, MAX(l_suppkey) FROM lineitem GROUP BY l_suppkey,l_orderkey"#,
    aggregate_min_by_1_col => r#"SELECT l_suppkey, MAX(l_suppkey) FROM lineitem GROUP BY l_suppkey,l_orderkey"#,
]);

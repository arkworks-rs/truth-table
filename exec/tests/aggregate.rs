mod support;

end_to_end_tests!(&["lineitem"] => [
    aggregate_count_by_1_col => r#"SELECT l_suppkey, COUNT(*) FROM lineitem GROUP BY l_suppkey"#,
    aggregate_count_by_2_cols => r#"SELECT l_suppkey, l_orderkey, COUNT(*) FROM lineitem GROUP BY l_suppkey, l_orderkey"#,
    aggregate_sum_by_2_cols => r#"SELECT l_suppkey, l_orderkey, SUM(l_extendedprice) FROM lineitem GROUP BY l_suppkey, l_orderkey"#,
    aggregate_max_by_2_cols => r#"SELECT l_suppkey, l_orderkey, MAX(l_extendedprice) FROM lineitem GROUP BY l_suppkey, l_orderkey"#,
    aggregate_min_by_2_cols => r#"SELECT l_suppkey, l_orderkey, MIN(l_extendedprice) FROM lineitem GROUP BY l_suppkey, l_orderkey"#,
]);

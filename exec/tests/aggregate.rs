mod support;
use support::end_to_end_tests;

end_to_end_tests!(&["lineitem"] => [
    aggregate_count_by_flag => r#"SELECT l_returnflag, COUNT(*) FROM lineitem GROUP BY l_returnflag"#,
    aggregate_sum_suppkeys_by_flag => r#"SELECT l_returnflag, SUM(l_suppkey) FROM lineitem GROUP BY l_returnflag"#,
    aggregate_max_orderkey_by_flag => r#"SELECT l_returnflag, MAX(l_orderkey) FROM lineitem GROUP BY l_returnflag"#,
    aggregate_min_orderkey_by_flag => r#"SELECT l_returnflag, MIN(l_orderkey) FROM lineitem GROUP BY l_returnflag"#,
]);

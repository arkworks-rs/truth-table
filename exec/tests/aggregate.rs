mod support;
use support::end_to_end_tests;

end_to_end_tests!("lineitem" => [
    aggregate_count_by_flag => r#"SELECT l_returnflag, COUNT(l_extendedprice) FROM lineitem GROUP BY  l_returnflag, l_linestatus "#,
    aggregate_sum_by_flag => r#"SELECT l_returnflag, SUM(l_extendedprice) FROM lineitem GROUP BY  l_returnflag,l_linestatus "#,
    aggregate_max_by_flag => r#"SELECT l_returnflag, MAX(l_extendedprice) FROM lineitem GROUP BY  l_returnflag,l_linestatus "#,
    aggregate_min_by_flag => r#"SELECT l_returnflag, MIN(l_extendedprice) FROM lineitem GROUP BY  l_returnflag,l_linestatus "#,
]);

#![cfg(feature = "test-utils")]

mod support;

end_to_end_tests!(&["nation"] => [
    limit_below_row_count => r#"SELECT n_name FROM nation LIMIT 5"#,
    limit_above_active_rows => r#"SELECT n_name FROM nation WHERE n_regionkey = 1 LIMIT 10"#,
    limit_after_filter => r#"SELECT n_name FROM nation WHERE n_nationkey > 10 LIMIT 3"#,
]);

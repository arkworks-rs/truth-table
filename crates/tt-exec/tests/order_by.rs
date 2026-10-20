#![cfg(feature = "test-utils")]

mod support;

end_to_end_tests!(&["nation"] => [
    order_by_filtered_desc => r#"SELECT n_nationkey, n_name FROM nation WHERE n_regionkey = 1 ORDER BY n_nationkey DESC"#,
    order_by_two_keys => r#"SELECT n_regionkey, n_name FROM nation ORDER BY n_regionkey, n_name"#,
    order_by_with_limit => r#"SELECT n_name FROM nation ORDER BY n_name LIMIT 3"#,
]);

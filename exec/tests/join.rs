mod support;
use support::end_to_end_tests;

end_to_end_tests!(&["lineitem", "supplier"] => [
    aggregate_count_by_flag => r#"SELECT l_suppkey, s_name
FROM lineitem l
JOIN supplier s ON l.l_suppkey = s.s_suppkey;
"#,
]);

mod support;
use support::end_to_end_tests;

end_to_end_tests!("lineitem" => [
    aggregate_count_by_flag => r#"SELECT
    l_returnflag,
    COUNT(*)
FROM
    lineitem
GROUP BY
    l_returnflag
"#,


]);

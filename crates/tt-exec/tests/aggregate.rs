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

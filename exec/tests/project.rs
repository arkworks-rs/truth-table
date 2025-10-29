#![cfg(feature = "test-utils")]

mod support;
use support::end_to_end_tests;

end_to_end_tests!(&["lineitem"] => [
    project_returns_flag_status => r#"SELECT l_returnflag, l_linestatus FROM lineitem"#,
    project_returns_shipdate => r#"SELECT l_shipdate FROM lineitem"#,
    project_returns_quantity_extprice => r#"SELECT l_quantity, l_extendedprice FROM lineitem "#,
]);

#![cfg(feature = "test-utils")]

mod support;

end_to_end_tests!(&["lineitem"] => [
    project_returns_flag_status => r#"SELECT l_returnflag, l_linestatus FROM lineitem"#,
    project_returns_shipdate => r#"SELECT l_shipdate FROM lineitem"#,
    project_returns_quantity_extprice => r#"SELECT l_quantity, l_extendedprice FROM lineitem "#,
]);

// A Decimal128 projection at a small scale (`part`, nv=14).
end_to_end_tests!(&["part"] => [
    project_retailprice_part => r#"SELECT p_retailprice FROM part"#,
]);

// One decimal column, against the two of `project_returns_quantity_extprice`.
end_to_end_tests!(&["lineitem"] => [
    project_extprice_only_lineitem => r#"SELECT l_extendedprice FROM lineitem"#,
]);

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

// `SELECT *` lists every column of the tables, including the system columns
// the parquet files carry; the plan must not project those as data.
end_to_end_tests!(&["nation"] => [
    select_star_nation => r#"SELECT * FROM nation"#,
]);

end_to_end_tests!(&["region", "nation"] => [
    select_star_join => r#"SELECT * FROM region, nation WHERE r_regionkey = n_regionkey"#,
]);

end_to_end_tests!(&["region", "nation", "supplier"] => [
    select_star_join_chain => r#"SELECT * FROM region, nation, supplier WHERE r_regionkey = n_regionkey AND n_nationkey = s_nationkey"#,
]);

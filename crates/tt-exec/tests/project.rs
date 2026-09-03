#![cfg(feature = "test-utils")]

mod support;

end_to_end_tests!(&["lineitem"] => [
    project_returns_flag_status => r#"SELECT l_returnflag, l_linestatus FROM lineitem"#,
    project_returns_shipdate => r#"SELECT l_shipdate FROM lineitem"#,
    project_returns_quantity_extprice => r#"SELECT l_quantity, l_extendedprice FROM lineitem "#,
]);

// Small-scale (part, nv=14) reproducer for the pre-existing
// VerifierTracker prover-comm ID mismatch bug — same failure mode as
// `project_returns_quantity_extprice` on lineitem, but 5× smaller for
// faster debug turns.  `p_retailprice` is Decimal128.
end_to_end_tests!(&["part"] => [
    project_retailprice_part => r#"SELECT p_retailprice FROM part"#,
]);

// Single-decimal projection on lineitem — narrower shape than
// `project_returns_quantity_extprice` (which selects two decimals) to
// isolate whether the tracker-ID bug depends on the number of decimal
// columns projected.
end_to_end_tests!(&["lineitem"] => [
    project_extprice_only_lineitem => r#"SELECT l_extendedprice FROM lineitem"#,
]);

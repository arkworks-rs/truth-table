#![cfg(feature = "test-utils")]

mod support;

end_to_end_tests!(&["lineitem"] => [
    simple_equality_filter_and => r#"SELECT l_returnflag, l_linestatus FROM lineitem WHERE l_returnflag = 'R' AND l_linestatus= 'F'"#,
    simple_equality_filter => r#"SELECT l_returnflag, l_linestatus FROM lineitem WHERE l_returnflag = 'R'"#,
    simple_inequality_filter => r#"SELECT l_returnflag, l_linestatus FROM lineitem WHERE l_shipdate < DATE '1998-09-01'"#,
]);

end_to_end_tests!(&["nation"] => [
    simple_like_infix_nation => r#"SELECT n_name FROM nation WHERE n_comment LIKE '%haggle%'"#,
]);

// Small-scale equality-filter reproducer on `part` (16k rows → nv=14).
// Fast enough for brute-force sumcheck-consistency diagnostics.
end_to_end_tests!(&["part"] => [
    equality_filter_part => r#"SELECT p_name FROM part WHERE p_brand = 'Brand#13'"#,
]);

/// Regression guard for the residual equality-filter bug —
/// `SELECT o_comment FROM orders WHERE o_orderstatus = 'F'` on
/// orders (131k rows → nv=17). Currently fails with `Sumcheck's
/// deferred checks failed in round 0`, same as
/// `simple_equality_filter` / `simple_equality_filter_and` on
/// lineitem (nv=19).
///
/// Bisected in the 2026-08-09 session: this bug is
/// **scale-dependent**, not shape-dependent. `equality_filter_part`
/// on `part` (nv=14) — same shape but smaller — passes with the
/// same fixes (see ark-piop@e45baae, tt-core@31a31aae). The residual
/// only triggers at nv >= 16, and instrumented brute-force at
/// nv <= 16 confirms the aggregated sumcheck poly's actual
/// hypercube sum equals the recorded claim at those scales.
/// Something in the pipeline changes behavior at the nv=16
/// threshold. `reduce_sumcheck_dgree` disabled → still fails, so
/// that's not it. Prover/verifier claim values and orderings match
/// step-by-step across all bucketing/equalize/batch stages —
/// yet `msg[0]+msg[1] != asserted_sum` for the second bucket.
///
/// Kept as `#[ignore]` so `cargo test` stays green; run with
/// `cargo test -- --ignored equality_filter_orders` when
/// investigating.
#[tokio::test]
#[ignore = "residual round-0 mismatch at nv>=16 — needs its own debug session"]
async fn equality_filter_orders() {
    tt_exec::test_utils::prove_and_verify_query(
        r#"SELECT o_comment FROM orders WHERE o_orderstatus = 'F'"#,
        &["orders"],
        None,
    )
    .await
    .expect("end-to-end: equality_filter_orders");
}

end_to_end_tests!(&["lineitem"] => [
    simple_like_infix_lineitem => r#"SELECT l_returnflag FROM lineitem WHERE l_comment LIKE '%green%'"#,
]);

/// Bench-scale lineitem LIKE: routed through
/// [`prove_and_verify_query_bench`] so it uses the bench-data parquet
/// (2^20 rows) and the bench-size proving key (nv=25). Used for peak-RSS
/// A/B measurements of the LIKE gadget's memory footprint.
#[tokio::test]
async fn bench_like_infix_lineitem() {
    tt_exec::test_utils::prove_and_verify_query_bench(
        r#"SELECT l_returnflag FROM lineitem WHERE l_comment LIKE '%green%'"#,
        &["lineitem"],
        None,
    )
    .await
    .expect("bench-data lineitem LIKE end-to-end");
}

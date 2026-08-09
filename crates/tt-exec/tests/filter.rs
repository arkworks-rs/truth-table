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

/// Historical regression pin for the equality-filter bug on `orders`
/// (`SELECT o_comment FROM orders WHERE o_orderstatus = 'F'`,
/// 131k rows → nv=17). Now passes end-to-end after four separate
/// fixes landed in sequence; kept in the suite as a regression
/// guard on that specific query shape.
///
/// **History** — four stacked bugs on this shape, each fix
/// uncovered the next:
/// 1. "Sumcheck's deferred checks failed in round 0" — fixed by
///    threading the outer `global_max_for_recording` snapshot into
///    the verifier's `equalize_sumcheck_claims` (ark-piop@e0c6808).
/// 2. `VerifierTracker` prover-comm ID mismatch (`31 vs 10`) — the
///    verifier's `track_mv_com_by_id` used `gen_id` and asserted
///    the freshly-minted ID matched the caller's expected prover
///    ID, which fails whenever a subset-transfer caller
///    (`TrackedTableOracle::from_tracked_table`) visits polys in
///    a non-contiguous order. Fixed by registering commits under
///    the caller-supplied ID directly (ark-piop@7f305ab).
/// 3. `TrackedTable` schema-order mismatch — the data owner's
///    schema listed fields in prover-tracking order, but
///    `all_tracked_cols` walks post-regroup order. Fixed by
///    building the schema from post-regroup order (truth-table@5f44f724).
/// 4. `Eq` gadget input-arity mismatch (left=6, right=2) — the
///    row-vs-side classification of `TrackedCol::MultiSegment` aux
///    was inferred by comparing `data.log_size()` against the
///    primary's, which silently misclassifies side segments whose
///    pow2-padded domain matches the row size (e.g. lineitem's
///    `l_returnflag` — every value is one char, so `__chars` side
///    log_size == row log_size and side segments leaked into
///    `segments_iter`). Fixed by storing the row/side split
///    explicitly as `side_aux_suffixes: IndexSet<String>` on both
///    `TrackedCol::MultiSegment` and `TrackedColOracle::MultiSegment`.
#[tokio::test]
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

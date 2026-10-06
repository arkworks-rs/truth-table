#![cfg(feature = "test-utils")]

mod support;

end_to_end_tests!(&["lineitem"] => [
    simple_equality_filter_and => r#"SELECT l_returnflag, l_linestatus FROM lineitem WHERE l_returnflag = 'R' AND l_linestatus= 'F'"#,
    simple_equality_filter => r#"SELECT l_returnflag, l_linestatus FROM lineitem WHERE l_returnflag = 'R'"#,
    simple_inequality_filter => r#"SELECT l_returnflag, l_linestatus FROM lineitem WHERE l_shipdate < DATE '1998-09-01'"#,
]);

end_to_end_tests!(&["nation"] => [
    simple_like_infix_nation => r#"SELECT n_name FROM nation WHERE n_comment LIKE '%haggle%'"#,
    // `%slyly%` leaves more pre-filter survivors than true matches (10 vs
    // 8 under the 128-bin rule), so `next_pow2(matches) < next_pow2(survivors)`
    // and the planner compacts a SECOND time after the LIKE — a rematerialize
    // + DPUC + lookup stage that the `%haggle%` shape never reaches. The
    // ORDER BY is what keeps that compaction: a LIKE whose output only
    // reaches a projection and the result check is no longer compacted.
    // Without this case the second-stage DPUC has no verifying coverage.
    like_infix_nation_second_compaction => r#"SELECT n_name FROM nation WHERE n_comment LIKE '%slyly%' ORDER BY n_name"#,
    // The same LIKE with nothing but the projection above it: the planner
    // now leaves its output uncompacted, and the result check takes the
    // LIKE's own domain.
    like_infix_nation_uncompacted_tail => r#"SELECT n_name FROM nation WHERE n_comment LIKE '%slyly%'"#,
    // Multi-factor LIKE: factors match in order, without overlap, and a row
    // that misses a factor is out (13 rows).
    like_two_factors_nation => r#"SELECT n_name FROM nation WHERE n_comment LIKE '%the%ly%'"#,
    // No row has the first factor, so nothing matches — even rows that
    // have the second one.
    like_first_factor_absent_nation => r#"SELECT n_name FROM nation WHERE n_comment LIKE '%zqzq%the%'"#,
    // A repeated factor needs two separate occurrences (17 rows).
    like_repeated_factor_nation => r#"SELECT n_name FROM nation WHERE n_comment LIKE '%ly%ly%'"#,
    // Suffix on the LAST string, whose successor slot is padding.
    like_suffix_last_string_nation => r#"SELECT n_name FROM nation WHERE n_comment LIKE '%be'"#,
    like_prefix_and_suffix_nation => r#"SELECT n_name FROM nation WHERE n_comment LIKE 'y%be'"#,
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

end_to_end_tests!(&["orders"] => [
    // `o_comment` (75 000 rows) gets its own rule at commit, like every
    // string column. The pattern matches 910 rows (1.2 %), so the
    // pre-filter really runs.
    like_infix_orders_special_requests => r#"SELECT o_orderkey FROM orders WHERE o_comment LIKE '%special%requests%'"#,
    // 5 110 survivors under the old entropy rule: 2^13 compacted rows with
    // 2^19 chars, so the rematerialization's offset no-dup sorts a column
    // of 2^19 rows. That size once broke the sort's window-function diffs
    // at a batch boundary (a zero diff the strict sign check rejects);
    // diffs are now computed on collected arrays for every integer type.
    like_infix_orders_final_requests => r#"SELECT o_orderkey FROM orders WHERE o_comment LIKE '%final%requests%'"#,
]);

end_to_end_tests!(&["lineitem"] => [
    simple_like_infix_lineitem => r#"SELECT l_returnflag FROM lineitem WHERE l_comment LIKE '%green%'"#,
    // Matches nothing, and the pre-filter's chosen bins keep no row either,
    // so the LIKE sees an empty input: its plan hints must still be built
    // from the padded empty table.
    like_prefilter_keeps_no_row => r#"SELECT l_returnflag FROM lineitem WHERE l_comment LIKE '%quickly%xylophone%'"#,
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

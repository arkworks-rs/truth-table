#![cfg(feature = "test-utils")]

mod support;
// use tt_core::test_display::{
//     display_prover_arithmetized_tree, display_prover_hint_tree,
// display_prover_piop_tree,     display_prover_proof_tree,
// display_prover_tracked_tree, };

end_to_end_tests!(&["supplier", "nation"] => [
    simple_join_1 => r#"SELECT
    s.s_suppkey,
    n.n_regionkey
FROM
    supplier s
JOIN
    nation n ON s.s_nationkey = n.n_nationkey
"#,
]);

end_to_end_tests!(&["supplier", "lineitem"] => [
    simple_join_2 => r#"SELECT
    l.l_orderkey,
    l.l_partkey,
    l.l_suppkey,
    s.s_name,
    s.s_nationkey
FROM
    lineitem AS l
JOIN
    supplier AS s
ON
    l.l_suppkey = s.s_suppkey;
"#,

]);
end_to_end_tests!(&["partsupp", "lineitem"] => [
    three_way_join => r#"SELECT
    l_orderkey,
    o_orderdate,
    o_shippriority
FROM
    customer,
    orders,
    lineitem
WHERE
    AND c_custkey = o_custkey
    AND l_orderkey = o_orderkey
"#,
]);

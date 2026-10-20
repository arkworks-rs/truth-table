#![cfg(feature = "test-utils")]

mod support;

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
end_to_end_tests!(&["orders", "lineitem", "customer"] => [
    three_way_join => r#"SELECT
    l_orderkey,
    o_orderdate,
    o_shippriority
FROM
    customer,
    orders,
    lineitem
WHERE
    c_custkey = o_custkey
    AND l_orderkey = o_orderkey;
"#,
]);

end_to_end_tests!(&["orders", "lineitem"] => [
    simple_self_join => r#"SELECT
    l1.l_orderkey,
    l1.l_linenumber,
    l2.l_linenumber
FROM
    lineitem l1
JOIN
    lineitem l2
ON
    l1.l_orderkey = l2.l_orderkey
"#,
]);

// Many-to-many joins: no side is joined on its primary key.
end_to_end_tests!(&["nation"] => [
    many_to_many_int_key => r#"SELECT n1.n_name, n2.n_name FROM nation n1 JOIN nation n2 ON n1.n_regionkey = n2.n_regionkey"#,
    many_to_many_string_key => r#"SELECT n1.n_nationkey, n2.n_regionkey FROM nation n1 JOIN nation n2 ON n1.n_name = n2.n_name"#,
    many_to_many_two_keys => r#"SELECT n1.n_nationkey, n2.n_nationkey FROM nation n1 JOIN nation n2 ON n1.n_regionkey = n2.n_regionkey AND n1.n_name = n2.n_name"#,
    many_to_many_filtered_side => r#"SELECT n1.n_name, n2.n_name FROM nation n1 JOIN nation n2 ON n1.n_regionkey = n2.n_regionkey WHERE n1.n_nationkey < 7"#,
]);

#[tokio::test]
#[should_panic(expected = "only inner equijoins")]
async fn left_join_is_not_supported() {
    let _ = tt_exec::test_utils::prove_and_verify_query(
        r#"SELECT n.n_name, r.r_name FROM nation n LEFT JOIN region r ON n.n_regionkey = r.r_regionkey"#,
        &["nation", "region"],
        None,
    )
    .await;
}

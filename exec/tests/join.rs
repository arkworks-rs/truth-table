#![cfg(feature = "test-utils")]

mod support;
// use truthtable_core::test_display::{
//     display_prover_arithmetized_tree, display_prover_hint_tree,
// display_prover_piop_tree,     display_prover_proof_tree,
// display_prover_tracked_tree, };

end_to_end_tests!(&["supplier", "nation"] => [
    join_supplier_nation_by_suppkey => r#"SELECT
    s.s_suppkey,
    n.n_regionkey
FROM
    supplier s
JOIN
    nation n ON s.s_nationkey = n.n_nationkey
"#,
]);

end_to_end_tests!(&["supplier", "lineitem"] => [
    join_supplier_lineitem_by_suppkey => r#"SELECT
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
    join_partsupp_lineitem_by_suppkey => r#"SELECT
    l.l_orderkey,
    l.l_linenumber,
    l.l_partkey,
    l.l_suppkey,
    ps.ps_availqty,
    ps.ps_supplycost
FROM
    lineitem AS l
JOIN
    partsupp AS ps
ON
    l.l_partkey = ps.ps_partkey
AND
    l.l_suppkey = ps.ps_suppkey;
"#,
]);
end_to_end_tests!(&["orders", "customer"] => [
    join_orders_customer_by_custkey => r#"
SELECT
    o_orderdate,
    o_shippriority
FROM
    customer,
    orders
WHERE
     c_custkey = o_custkey
    "#
]);
end_to_end_tests!(&["orders", "lineitem"] => [
    join_orders_lineitem_by_orderkey => r#"
SELECT
    o_orderdate,
    o_shippriority
FROM
    lineitem,
    orders
WHERE
     l_orderkey = o_orderkey
    "#
]);

end_to_end_tests!(&["orders", "lineitem", "customer"] => [
    join_orders_lineitem_customer_by_custkey => r#"
SELECT
    o_orderdate,
    o_shippriority
FROM
    lineitem,
    orders,
    customer
WHERE
    l_orderkey = o_orderkey
     AND c_custkey = o_custkey
    "#
]);


// #[tokio::test]
// #[ignore = "Visualization-focused test"]
// async fn display_join_prover_proof_tree() {
//     let sql = "SELECT l_suppkey, s_name
// FROM lineitem l
// JOIN supplier s ON l.l_suppkey = s.s_suppkey;
// ";
//     let ctx  = new_session_context_with_custom_analyzer();
//     let lineitem_path = tpch_data::test_data_path("lineitem.parquet");
//     let supplier_path = tpch_data::test_data_path("supplier.parquet");
//     ctx.register_parquet(
//         "lineitem",
//         lineitem_path
//             .to_str()
//             .expect("lineitem path to be valid UTF-8"),
//         ParquetReadOptions::default(),
//     )
//     .await
//     .expect("register lineitem table");
//     ctx.register_parquet(
//         "supplier",
//         supplier_path
//             .to_str()
//             .expect("supplier path to be valid UTF-8"),
//         ParquetReadOptions::default(),
//     )
//     .await
//     .expect("register lineitem table");
//     let proof_tree = create_prover_proof_tree::<F, MvPCS, UvPCS>(&ctx,
// sql).await;     display_prover_proof_tree(&proof_tree).await;
// }

// // #[tokio::test]
// // #[ignore = "Visualization-focused test"]
// // async fn display_join_prover_hint_tree() {
// //     let sql = "SELECT l_suppkey, s_name
// // FROM lineitem l
// // JOIN supplier s ON l.l_suppkey = s.s_suppkey;
// // ";
// //     let ctx = new_session_context_with_custom_analyzer();
// //     let lineitem_path = tpch_data::test_data_path("lineitem.parquet");
// //     let supplier_path = tpch_data::test_data_path("supplier.parquet");
// //     ctx.register_parquet(
// //         "lineitem",
// //         lineitem_path
// //             .to_str()
// //             .expect("lineitem path to be valid UTF-8"),
// //         ParquetReadOptions::default(),
// //     )
// //     .await
// //     .expect("register lineitem table");
// //     ctx.register_parquet(
// //         "supplier",
// //         supplier_path
// //             .to_str()
// //             .expect("supplier path to be valid UTF-8"),
// //         ParquetReadOptions::default(),
// //     )
// //     .await
// //     .expect("register lineitem table");
// //     let proof_tree = create_prover_proof_tree::<F, MvPCS, UvPCS>(&ctx,
// // sql).await;     display_prover_hint_tree(&ctx, proof_tree).await;
// // }

// // #[tokio::test]
// // #[ignore = "Visualization-focused test"]
// // async fn display_join_prover_arithmetized_tree() {
// //     let sql = "SELECT l_suppkey, s_name
// // FROM lineitem l
// // JOIN supplier s ON l.l_suppkey = s.s_suppkey;
// // ";
// //     let ctx = new_session_context_with_custom_analyzer();
// //     let lineitem_path = tpch_data::test_data_path("lineitem.parquet");
// //     let supplier_path = tpch_data::test_data_path("supplier.parquet");
// //     ctx.register_parquet(
// //         "lineitem",
// //         lineitem_path
// //             .to_str()
// //             .expect("lineitem path to be valid UTF-8"),
// //         ParquetReadOptions::default(),
// //     )
// //     .await
// //     .expect("register lineitem table");
// //     ctx.register_parquet(
// //         "supplier",
// //         supplier_path
// //             .to_str()
// //             .expect("supplier path to be valid UTF-8"),
// //         ParquetReadOptions::default(),
// //     )
// //     .await
// //     .expect("register lineitem table");
// //     let proof_tree = create_prover_proof_tree::<F, MvPCS, UvPCS>(&ctx,
// // sql).await;     display_prover_arithmetized_tree(&ctx, proof_tree).await;
// // }

// // #[tokio::test]
// // #[ignore = "Visualization-focused test"]
// // async fn display_join_prover_tracked_tree() {
// //     let sql = "SELECT l_suppkey, s_name
// // FROM lineitem l
// // JOIN supplier s ON l.l_suppkey = s.s_suppkey;
// // ";
// //     let ctx = new_session_context_with_custom_analyzer();
// //     let lineitem_path = tpch_data::test_data_path("lineitem.parquet");
// //     let supplier_path = tpch_data::test_data_path("supplier.parquet");
// //     ctx.register_parquet(
// //         "lineitem",
// //         lineitem_path
// //             .to_str()
// //             .expect("lineitem path to be valid UTF-8"),
// //         ParquetReadOptions::default(),
// //     )
// //     .await
// //     .expect("register lineitem table");
// //     ctx.register_parquet(
// //         "supplier",
// //         supplier_path
// //             .to_str()
// //             .expect("supplier path to be valid UTF-8"),
// //         ParquetReadOptions::default(),
// //     )
// //     .await
// //     .expect("register lineitem table");
// //     let proof_tree = create_prover_proof_tree::<F, MvPCS, UvPCS>(&ctx,
// // sql).await;     display_prover_tracked_tree(&ctx, proof_tree).await;
// // }

// // #[tokio::test]
// // #[ignore = "Visualization-focused test"]
// // async fn display_join_prover_piop_tree() {
// //     let sql = "SELECT l_suppkey, s_name
// // FROM lineitem l
// // JOIN supplier s ON l.l_suppkey = s.s_suppkey;
// // ";
// //     let ctx = new_session_context_with_custom_analyzer();
// //     let lineitem_path = tpch_data::test_data_path("lineitem.parquet");
// //     let supplier_path = tpch_data::test_data_path("supplier.parquet");
// //     ctx.register_parquet(
// //         "lineitem",
// //         lineitem_path
// //             .to_str()
// //             .expect("lineitem path to be valid UTF-8"),
// //         ParquetReadOptions::default(),
// //     )
// //     .await
// //     .expect("register lineitem table");
// //     ctx.register_parquet(
// //         "supplier",
// //         supplier_path
// //             .to_str()
// //             .expect("supplier path to be valid UTF-8"),
// //         ParquetReadOptions::default(),
// //     )
// //     .await
// //     .expect("register lineitem table");
// //     let proof_tree = create_prover_proof_tree::<F, MvPCS, UvPCS>(&ctx,
// // sql).await;     display_prover_piop_tree(&ctx, proof_tree).await;
// // }

// use crate::test_utils::helper::prove_and_verify_query;

// const QUERY_SPEC_1: (&str, &str) = (
//     "customer",
//     r#"
//         SELECT
//             c_nationkey,
//             c_custkey + c_nationkey AS cust_plus_nation,
//             SUM(c_acctbal * c_acctbal) AS total_energy,
//             AVG(c_acctbal) AS avg_balance,
//             COUNT(DISTINCT c_custkey) AS distinct_customers
//         FROM customer
//         GROUP BY c_nationkey, c_custkey + c_nationkey
//     "#,
// );

// #[test]
// fn prove_count_aggregate() {
//     prove_and_verify_query(
//         r#"
//         SELECT
//             l_suppkey,
//             l_linenumber,
//             COUNT(l_orderkey)
//         FROM lineitem
//         GROUP BY l_suppkey, l_linenumber
//     "#,
//         "lineitem",
//     );
// }

// #[test]
// fn prove_sum_aggregate() {
//     prove_and_verify_query(
//         r#"
//         SELECT
//             l_suppkey,
//             l_linenumber,
//             SUM(l_orderkey)
//         FROM lineitem
//         GROUP BY l_suppkey, l_linenumber
//     "#,
//         "lineitem",
//     );
// }
// #[test]
// fn prove_max_aggregate() {
//     prove_and_verify_query(
//         r#"
//         SELECT
//             l_suppkey,
//             l_linenumber,
//             MAX(l_orderkey)
//         FROM lineitem
//         GROUP BY l_suppkey, l_linenumber
//     "#,
//         "lineitem",
//     );
// }
// #[test]
// fn prove_min_aggregate() {
//     prove_and_verify_query(
//         r#"
//         SELECT
//             l_suppkey,
//             l_linenumber,
//             MIN(l_orderkey)
//         FROM lineitem
//         GROUP BY l_suppkey, l_linenumber
//     "#,
//         "lineitem",
//     );
// }

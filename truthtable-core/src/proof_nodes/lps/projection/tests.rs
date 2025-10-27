// use crate::test_utils::helper::prove_and_verify_query;

// #[test]
// fn prove_projection() {
//     prove_and_verify_query("SELECT l_partkey FROM lineitem", "lineitem");
// }

// #[test]
// fn proves_multi_column_projection() {
//     prove_and_verify_query("SELECT l_orderkey, l_suppkey FROM lineitem",
// "lineitem"); }
// #[test]
// fn proves_addition_projection() {
//     prove_and_verify_query("SELECT l_partkey+l_orderkey FROM lineitem",
// "lineitem"); }

// #[test]
// fn proves_subtraction_projection() {
//     prove_and_verify_query("SELECT l_partkey-l_orderkey FROM lineitem",
// "lineitem"); }

// #[test]
// fn proves_multiplication_projection() {
//     prove_and_verify_query("SELECT l_partkey*l_orderkey FROM lineitem",
// "lineitem"); }

// #[test]
// fn proves_algebraic_projection() {
//     prove_and_verify_query(
//         "SELECT l_partkey*(l_orderkey + l_suppkey)- l_partkey FROM lineitem",
//         "lineitem",
//     );
// }

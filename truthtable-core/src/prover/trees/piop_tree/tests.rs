// use crate::test_display::display_prover_piop_tree;
// use datafusion::error::Result as DFResult;

// #[tokio::test]
// #[ignore = "This test is for visualization purposes and may require manual
// inspection."] async fn can_display_prover_proof_trees() -> DFResult<()> {
//     display_prover_piop_tree(
//         &["lineitem"],
//         "SELECT l_orderkey FROM lineitem WHERE l_quantity >= l_suppkey",
//     )
//     .await;
//     display_prover_piop_tree(
//         &["lineitem"],
//         "SELECT l_partkey,l_discount FROM lineitem where l_suppkey+20 >
// l_partkey*2-l_orderkey",     )
//     .await;
//     Ok(())
// }

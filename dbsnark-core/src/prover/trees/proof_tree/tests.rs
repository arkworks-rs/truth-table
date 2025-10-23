use crate::test_display::display_prover_proof_tree;

#[tokio::test]
#[ignore = "This test is for visualization purposes and may require manual inspection."]
async fn can_display_prover_proof_trees() {
    display_prover_proof_tree(
        &["lineitem"],
        "SELECT l_suppkey+l_partkey, l_extendedprice FROM lineitem where l_quantity+l_linenumber == 5 ",
    )
    .await;
    // display_proof_tree(
    //     "lineitem",
    //     "SELECT count(l_partkey) FROM lineitem GROUP BY l_quantity",
    // )
    // .await;
}

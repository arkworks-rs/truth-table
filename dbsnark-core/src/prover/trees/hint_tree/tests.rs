use crate::test_display::display_prover_hint_tree;

#[tokio::test]
#[ignore = "This test is for visualization purposes and may require manual inspection."]
async fn can_display_prover_hint_trees() {
    display_prover_hint_tree(
        &["lineitem"],
        "SELECT l_suppkey+l_partkey, l_extendedprice FROM lineitem where l_quantity+l_linenumber == 5 ",
    )
    .await;
    // display_prover_hint_tree(
    //     "lineitem",
    //     "SELECT count(l_partkey) FROM lineitem GROUP BY 2*l_quantity",
    // )
    // .await;
}

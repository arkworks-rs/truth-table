mod support;
use datafusion::prelude::ParquetReadOptions;
use proof_planner::{create_prover_proof_tree, new_session_context_with_custom_analyzer};
use support::end_to_end_tests;
use truthtable_core::test_display::display_prover_hint_tree;

end_to_end_tests!(&["lineitem"] => [
    group_by_project_order_by_key => r#"
        SELECT l_suppkey
        FROM lineitem
        ORDER BY l_suppkey ASC;
    "#,
    // group_by_project_order_by_aggregate_desc => r#"
    //     SELECT
    //         l_returnflag,
    //         SUM(l_quantity) AS total_quantity
    //     FROM lineitem
    //     GROUP BY l_returnflag
    //     ORDER BY total_quantity DESC
    // "#,
    // group_by_project_order_by_multiple_keys => r#"
    //     SELECT
    //         l_returnflag,
    //         l_shipmode
    //     FROM lineitem
    //     GROUP BY l_returnflag, l_shipmode
    //     ORDER BY l_returnflag ASC, l_shipmode DESC
    // "#,
]);

type F = ark_test_curves::bls12_381::Fr;
type MvPCS = ark_piop::pcs::pst13::PST13<ark_test_curves::bls12_381::Bls12_381>;
type UvPCS = ark_piop::pcs::kzg10::KZG10<ark_test_curves::bls12_381::Bls12_381>;

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn display_sort_prover_hint_tree() {
    let sql = "
            SELECT l_suppkey
        FROM lineitem
        ORDER BY l_suppkey ASC;
";
    let ctx = new_session_context_with_custom_analyzer();
    let lineitem_path = tpch_data::test_data_path("lineitem.parquet");
    ctx.register_parquet(
        "lineitem",
        lineitem_path
            .to_str()
            .expect("lineitem path to be valid UTF-8"),
        ParquetReadOptions::default(),
    )
    .await
    .expect("register lineitem table");

    let proof_tree = create_prover_proof_tree::<F, MvPCS, UvPCS>(&ctx, sql).await;
    display_prover_hint_tree(&ctx, proof_tree).await;
}

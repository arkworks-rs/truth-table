mod support;
use datafusion::prelude::ParquetReadOptions;
use proof_planner::{create_prover_proof_tree, new_session_context_with_custom_analyzer};
use support::end_to_end_tests;
use truthtable_core::test_display::display_prover_hint_tree;

end_to_end_tests!(&["lineitem"] => [
    project_sort => r#"
        SELECT l_suppkey
        FROM lineitem
        ORDER BY l_suppkey ASC;
    "#,
    project_sort_1 => r#"
SELECT 
    l_suppkey,
    (l_suppkey * 7 + 3) AS computed_key
FROM lineitem
ORDER BY 4 + (l_suppkey * 7 + 3) DESC, l_suppkey ASC;
    "#,
    filter_sort => r#"
        SELECT 
    l_suppkey,
    (l_suppkey * 7 + 3) AS computed_key
FROM lineitem
WHERE l_suppkey > 1000
ORDER BY 4 +  (l_suppkey * 7 + 3) DESC, l_suppkey ASC;"#,
]);

type F = ark_test_curves::bls12_381::Fr;
type MvPCS = ark_piop::pcs::pst13::PST13<ark_test_curves::bls12_381::Bls12_381>;
type UvPCS = ark_piop::pcs::kzg10::KZG10<ark_test_curves::bls12_381::Bls12_381>;

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn display_sort_prover_hint_tree() {
    let sql = "
SELECT 
    l_suppkey,
    (l_suppkey * 7 + 3) AS computed_key
FROM lineitem
ORDER BY 4+computed_key DESC, l_suppkey ASC;
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

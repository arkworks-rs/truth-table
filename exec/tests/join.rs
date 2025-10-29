mod support;
use datafusion::prelude::ParquetReadOptions;
use proof_planner::{create_prover_proof_tree, new_session_context_with_custom_analyzer};
use support::end_to_end_tests;
use truthtable_core::test_display::display_prover_proof_tree;

end_to_end_tests!(&["lineitem", "supplier"] => [
    aggregate_count_by_flag => r#"SELECT l_suppkey, s_name
FROM lineitem l
JOIN supplier s ON l.l_suppkey = s.s_suppkey;
"#,
]);

type F = ark_test_curves::bls12_381::Fr;
type MvPCS = ark_piop::pcs::pst13::PST13<ark_test_curves::bls12_381::Bls12_381>;
type UvPCS = ark_piop::pcs::kzg10::KZG10<ark_test_curves::bls12_381::Bls12_381>;

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q1_proof_tree() {
    let sql = "SELECT l_suppkey, s_name
FROM lineitem l
JOIN supplier s ON l.l_suppkey = s.s_suppkey;
";
    let ctx = new_session_context_with_custom_analyzer();
    let lineitem_path = tpch_data::test_data_path("lineitem.parquet");
    let supplier_path = tpch_data::test_data_path("supplier.parquet");
    ctx.register_parquet(
        "lineitem",
        lineitem_path
            .to_str()
            .expect("lineitem path to be valid UTF-8"),
        ParquetReadOptions::default(),
    )
    .await
    .expect("register lineitem table");
    ctx.register_parquet(
        "supplier",
        supplier_path
            .to_str()
            .expect("supplier path to be valid UTF-8"),
        ParquetReadOptions::default(),
    )
    .await
    .expect("register lineitem table");
    let proof_tree = create_prover_proof_tree::<F, MvPCS, UvPCS>(&ctx, sql).await;
    display_prover_proof_tree(&proof_tree).await;
}

use ark_piop::pcs::{kzg10::KZG10, pst13::PST13};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::prelude::{ParquetReadOptions, SessionContext};
use proof_planner::create_prover_proof_tree;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;
#[tokio::test]
#[ignore = "For visualization purposes"]
async fn create_prover_proof_tree_panics_until_implemented() {
    let ctx = SessionContext::new();
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

    let query = "SELECT
    l_returnflag,
    l_linestatus,
    SUM(l_discount + 2) AS sum_disc_price
FROM
    lineitem
GROUP BY
    l_returnflag,
    l_linestatus";
    let proof_plan = create_prover_proof_tree::<Fr, MvPCS, UvPCS>(&ctx, query).await;
    println!("{}", proof_plan.display_graphviz());
}

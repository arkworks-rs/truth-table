use datafusion::prelude::{ParquetReadOptions, SessionContext};
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

    let _query = "SELECT
    l_returnflag,
    l_linestatus,
    SUM(l_discount + 2) AS sum_disc_price
FROM
    lineitem
GROUP BY
    l_returnflag,
    l_linestatus";
    // let proof_plan = create_prover_proof_tree::<DefaultSnarkBackend>(&ctx, query).await;
}

#![cfg(feature = "test-utils")]

use ark_piop::pcs::{kzg10::KZG10, pst13::PST13};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::prelude::{ParquetReadOptions, SessionContext};
use dbsnark_core::{
    test_display::{
        display_prover_arithmetized_tree, display_prover_hint_tree, display_prover_piop_tree,
        display_prover_proof_tree, display_prover_tracked_tree,
    },
    test_utils::helper::prove_and_verify_query,
};
use proof_planner::{
    create_prover_proof_tree, create_verifier_proof_tree, new_session_context_with_custom_analyzer,
};
use tpch_data::query_spec;

fn spec() -> tpch_data::TpchQuerySpec {
    query_spec(1)
}

type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q1_proof_tree() {
    let spec = spec();
    let sql = "SELECT
    l_returnflag,
    l_linestatus,
    SUM(l_discount + 2) AS sum_disc_price
FROM
    lineitem
GROUP BY
    l_returnflag,
    l_linestatus
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
    display_prover_proof_tree(&proof_tree).await;
}

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q1_hint_tree() {
    let spec = spec();
    let sql = "SELECT
    l_returnflag,
    l_linestatus,
    SUM(l_discount + 2) AS sum_disc_price
FROM
    lineitem
GROUP BY
    l_returnflag,
    l_linestatus
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

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q1_arithmetized_tree() {
    let spec = spec();

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
    let proof_tree = create_prover_proof_tree::<F, MvPCS, UvPCS>(&ctx, spec.sql).await;
    display_prover_arithmetized_tree(&ctx, proof_tree).await;
}

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q1_tracked_tree() {
    let spec = spec();

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
    let proof_tree = create_prover_proof_tree::<F, MvPCS, UvPCS>(&ctx, spec.sql).await;
    display_prover_tracked_tree(&ctx, proof_tree).await;
}

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q1_piop_tree() {
    let spec = spec();

    let sql = "SELECT
    l_returnflag,
    l_linestatus,
    SUM(l_discount + 2) AS sum_disc_price
FROM
    lineitem
GROUP BY
    l_returnflag,
    l_linestatus
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
    display_prover_piop_tree(&ctx, proof_tree).await;
}

#[tokio::test]
async fn tpch_q1_prove_verify() {
    // let spec = spec();
    let sql = "SELECT
    l_returnflag,
    l_linestatus,
    SUM(l_discount+2) AS sum_disc_price
FROM
    lineitem
GROUP BY
    l_returnflag,
    l_linestatus
";
    let lineitem_path = tpch_data::test_data_path("lineitem.parquet");

    let prover_ctx = new_session_context_with_custom_analyzer();
    prover_ctx
        .register_parquet(
            "lineitem",
            lineitem_path
                .to_str()
                .expect("lineitem path to be valid UTF-8"),
            ParquetReadOptions::default(),
        )
        .await
        .expect("register lineitem table for prover");

    let verifier_ctx = new_session_context_with_custom_analyzer();
    verifier_ctx
        .register_parquet(
            "lineitem",
            lineitem_path
                .to_str()
                .expect("lineitem path to be valid UTF-8"),
            ParquetReadOptions::default(),
        )
        .await
        .expect("register lineitem table for verifier");

    let prover_proof_tree = create_prover_proof_tree::<F, MvPCS, UvPCS>(&prover_ctx, sql).await;
    let verifier_proof_tree =
        create_verifier_proof_tree::<F, MvPCS, UvPCS>(&verifier_ctx, sql).await;
    prove_and_verify_query(&verifier_ctx, prover_proof_tree, verifier_proof_tree).await;
}

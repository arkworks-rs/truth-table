#![cfg(feature = "test-utils")]

use ark_piop::pcs::{kzg10::KZG10, pst13::PST13};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::prelude::{ParquetReadOptions, SessionContext};
use proof_planner::{
    create_prover_proof_tree, create_verifier_proof_tree, new_session_context_with_custom_analyzer,
};
use tpch_data::query_spec;
use truthtable_core::test_display::{
    display_prover_arithmetized_tree, display_prover_hint_tree, display_prover_piop_tree,
    display_prover_proof_tree, display_prover_tracked_tree,
};

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

    let sql = "        SELECT
    l_returnflag,
    l_linestatus,
    SUM(l_quantity) AS sum_qty,
    SUM(l_extendedprice) AS sum_base_price,
    SUM(l_extendedprice * (1 - l_discount)) AS sum_disc_price,
    SUM(l_extendedprice * (1 - l_discount) * (1 + l_tax)) AS sum_charge
FROM
    lineitem
WHERE
    l_shipdate <= CAST('1998-09-02' AS DATE)
GROUP BY
    l_returnflag,
    l_linestatus
ORDER BY
    l_returnflag,
    l_linestatus;
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
    let spec = spec();
    let sql = "
        SELECT
    l_returnflag,
    l_linestatus,
    SUM(l_quantity) AS sum_qty,
    SUM(l_extendedprice) AS sum_base_price,
    SUM(l_extendedprice * (1 - l_discount)) AS sum_disc_price,
    SUM(l_extendedprice * (1 - l_discount) * (1 + l_tax)) AS sum_charge
FROM
    lineitem
WHERE
    l_shipdate <= CAST('1998-09-02' AS DATE)
GROUP BY
    l_returnflag,
    l_linestatus
ORDER BY
    l_returnflag,
    l_linestatus;
    ";
    // dbg!(&spec.sql);
    exec::test_utils::prove_and_verify_query(sql, spec.tables[0], None)
        .await
        .expect("prove and verify tpch q1");
}

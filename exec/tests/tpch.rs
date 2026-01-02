#![cfg(feature = "test-utils")]

use anyhow::Result;
use ark_piop::DefaultSnarkBackend;
use exec::prove::ProveBuilder;
use exec::setup::DEFAULT_TEST_LOG_SIZE;
use exec::test_utils::{resolve_key_paths, resolve_oracle_path, resolve_parquet_path};
use front_end::prover::ProverIrStages;
use tpch_data::query_spec;

type B = DefaultSnarkBackend;

async fn build_prover_stages(query: &str, table_names: &[&str]) -> Result<ProverIrStages<B>> {
    let parquet_paths = table_names
        .iter()
        .map(|name| resolve_parquet_path(name))
        .collect::<Result<Vec<_>>>()?;
    let (pk_path, _vk_path) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE)?;
    let mut oracle_paths = Vec::with_capacity(parquet_paths.len());
    for parquet_path in &parquet_paths {
        let oracle_path = resolve_oracle_path(parquet_path, &pk_path).await?;
        oracle_paths.push(oracle_path);
    }

    let runner = ProveBuilder::new()
        .with_query(query.to_string())
        .with_parquet_paths(parquet_paths)
        .with_oracle_paths(oracle_paths)
        .with_pk_path(pk_path)
        .build()?;

    let prover = runner.build_tt_prover().await?;
    let (stages, _arg_prover) = prover.build_ir_stages(query).await?;
    Ok(stages)
}

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q1_proof_tree() {
    let spec = query_spec(5);
    let stages = build_prover_stages(spec.sql, spec.tables)
        .await
        .expect("build prover stages");
    println!("{}", stages.initial.display_graphviz(true));
}

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q1_hint_tree() {
    let spec = query_spec(1);
    let stages = build_prover_stages(spec.sql, spec.tables)
        .await
        .expect("build prover stages");
    println!("{}", stages.planned.display_graphviz(true));
}

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q1_arithmetized_tree() {
    let spec = query_spec(1);
    let stages = build_prover_stages(spec.sql, spec.tables)
        .await
        .expect("build prover stages");
    println!("{}", stages.arithmetized.display_graphviz(true));
}

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q1_tracked_tree() {
    let spec = query_spec(1);
    let stages = build_prover_stages(spec.sql, spec.tables)
        .await
        .expect("build prover stages");
    println!("{}", stages.tracked.display_graphviz(true));
}

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q1_piop_tree() {
    let spec = query_spec(1);
    let stages = build_prover_stages(spec.sql, spec.tables)
        .await
        .expect("build prover stages");
    println!("{}", stages.gadget_ready.display_graphviz(true));
}

#[tokio::test]
async fn tpch_q1_prove_verify() {
    let spec = query_spec(1);

    exec::test_utils::prove_and_verify_query(spec.sql, spec.tables, None)
        .await
        .expect("prove and verify tpch q1");
}
#[tokio::test]
async fn tpch_q3_prove_verify() {
    let spec = query_spec(3);

    let sql = "SELECT
    l_orderkey,
    o_orderdate,
    o_shippriority
FROM
    customer,
    orders,
    lineitem
WHERE
     c_custkey = o_custkey
    AND l_orderkey = o_orderkey
";
    exec::test_utils::prove_and_verify_query(sql, spec.tables, None)
        .await
        .expect("prove and verify tpch q3");
}

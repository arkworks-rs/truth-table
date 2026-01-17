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
async fn tpch_q1_prove_verify() {
    let spec = query_spec(1);
    exec::test_utils::prove_and_verify_query(spec.sql, spec.tables, None)
        .await
        .expect("prove and verify tpch q1");
}

#[tokio::test]
async fn tpch_q3_prove_verify() {
    let spec = query_spec(3);
    exec::test_utils::prove_and_verify_query(spec.sql, spec.tables, None)
        .await
        .expect("prove and verify tpch q3");
}

#[tokio::test]
async fn tpch_q5_prove_verify() {
    let spec = query_spec(5);
    exec::test_utils::prove_and_verify_query(spec.sql, spec.tables, None)
        .await
        .expect("prove and verify tpch q5");
}

#[tokio::test]
async fn tpch_q8_prove_verify() {
    let spec = query_spec(8);
    exec::test_utils::prove_and_verify_query(spec.sql, spec.tables, None)
        .await
        .expect("prove and verify tpch q8");
}

#[tokio::test]
async fn tpch_q9_prove_verify() {
    let spec = query_spec(9);
    let simplified_sql = "SELECT
    nation,
    o_year,
    sum(amount) AS sum_profit
FROM (
    SELECT
        n_name AS nation,
        date_part('year', o_orderdate) AS o_year,
        l_extendedprice * (1 - l_discount) - ps_supplycost * l_quantity AS amount
    FROM
        part,
        supplier,
        lineitem,
        partsupp,
        orders,
        nation
    WHERE
        s_suppkey = l_suppkey
        AND ps_suppkey = l_suppkey
        AND ps_partkey = l_partkey
        AND p_partkey = l_partkey
        AND o_orderkey = l_orderkey
        AND s_nationkey = n_nationkey) AS profit
GROUP BY
    nation,
    o_year
ORDER BY
    nation,
    o_year DESC;";
    exec::test_utils::prove_and_verify_query(simplified_sql, spec.tables, None)
        .await
        .expect("prove and verify tpch q9");
}

#[tokio::test]
async fn tpch_q18_prove_verify() {
    let spec = query_spec(18);
    exec::test_utils::prove_and_verify_query(spec.sql, spec.tables, None)
        .await
        .expect("prove and verify tpch q18");
}

#[tokio::test]
async fn tpch_q19_prove_verify() {
    let spec = query_spec(19);
    exec::test_utils::prove_and_verify_query(spec.sql, spec.tables, None)
        .await
        .expect("prove and verify tpch q19");
}

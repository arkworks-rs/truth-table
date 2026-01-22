#![cfg(feature = "test-utils")]

use anyhow::Result;
use ark_piop::DefaultSnarkBackend;
use exec::prove::ProveBuilder;
use exec::setup::DEFAULT_TEST_LOG_SIZE;
use exec::test_utils::{resolve_key_paths, resolve_oracle_path, resolve_parquet_path};
use front_end::prover::ProverIrStages;
use tpch_data::query_spec;

#[allow(dead_code)]
async fn build_prover_stages(
    query: &str,
    table_names: &[&str],
) -> Result<ProverIrStages<DefaultSnarkBackend>> {
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
// TPCH Q8
//
// SELECT
//     o_year,
//     sum(
//         CASE WHEN nation = 'BRAZIL' THEN
//             volume
//         ELSE
//             0
//         END) / sum(volume) AS mkt_share
// FROM (
//     SELECT
//         date_part('year', o_orderdate) AS o_year,
//         l_extendedprice * (1 - l_discount) AS volume,
//         n2.n_name AS nation
//     FROM
//         part,
//         supplier,
//         lineitem,
//         orders,
//         customer,
//         nation n1,
//         nation n2,
//         region
//     WHERE
//         p_partkey = l_partkey
//         AND s_suppkey = l_suppkey
//         AND l_orderkey = o_orderkey
//         AND o_custkey = c_custkey
//         AND c_nationkey = n1.n_nationkey
//         AND n1.n_regionkey = r_regionkey
//         AND r_name = 'AMERICA'
//         AND s_nationkey = n2.n_nationkey
//         AND o_orderdate BETWEEN CAST('1995-01-01' AS date)
//         AND CAST('1996-12-31' AS date)
//         AND p_type = 'ECONOMY ANODIZED STEEL') AS all_nations
// GROUP BY
//     o_year
// ORDER BY
//     o_year;
#[tokio::test]
async fn tpch_q8_prove_verify() {
    let spec = query_spec(8);
    let simplified_sql = "
    SELECT
    o_year
FROM (
    SELECT
        o_orderdate AS o_year,
        l_extendedprice * (1 - l_discount) AS volume
    FROM
        part,
        supplier,
        lineitem,
        orders,
        customer,
        nation n1,
        region
    WHERE
        p_partkey = l_partkey
        AND s_suppkey = l_suppkey
        AND l_orderkey = o_orderkey
        AND o_custkey = c_custkey
        AND c_nationkey = n1.n_nationkey
        AND n1.n_regionkey = r_regionkey
        AND r_name = 'AMERICA'
        AND o_orderdate BETWEEN CAST('1995-01-01' AS date)
        AND CAST('1996-12-31' AS date)
        AND p_type = 'ECONOMY ANODIZED STEEL') AS all_nations
GROUP BY
    o_year
ORDER BY
    o_year;
";
    exec::test_utils::prove_and_verify_query(simplified_sql, spec.tables, None)
        .await
        .expect("prove and verify tpch q8");
}

// TPCH Q9
//
// SELECT
//     nation,
//     o_year,
//     sum(amount) AS sum_profit
// FROM (
//     SELECT
//         n_name AS nation,
//         date_part('year', o_orderdate) AS o_year,
//         l_extendedprice * (1 - l_discount) - ps_supplycost * l_quantity AS amount
//     FROM
//         part,
//         supplier,
//         lineitem,
//         partsupp,
//         orders,
//         nation
//     WHERE
//         s_suppkey = l_suppkey
//         AND ps_suppkey = l_suppkey
//         AND ps_partkey = l_partkey
//         AND p_partkey = l_partkey
//         AND o_orderkey = l_orderkey
//         AND s_nationkey = n_nationkey
//         AND p_name LIKE '%green%') AS profit
// GROUP BY
//     nation,
//     o_year
// ORDER BY
//     nation,
//     o_year DESC;

#[tokio::test]
async fn tpch_q9_prove_verify() {
    let spec = query_spec(9);
    println!("TPCH Q9 SQL:\n{}", spec.sql);
    let simplified_sql = "SELECT
    nation,
    o_year
FROM (
    SELECT
        n_name AS nation,
        o_orderdate AS o_year,
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
";
    exec::test_utils::prove_and_verify_query(simplified_sql, spec.tables, None)
        .await
        .expect("prove and verify tpch q9");
}

// TPCH Q18
//
// SELECT
//     c_name,
//     c_custkey,
//     o_orderkey,
//     o_orderdate,
//     o_totalprice,
//     sum(l_quantity)
// FROM
//     customer,
//     orders,
//     lineitem
// WHERE
//     o_orderkey IN (
//         SELECT
//             l_orderkey
//         FROM
//             lineitem
//         GROUP BY
//             l_orderkey
//         HAVING
//             sum(l_quantity) > 300)
//     AND c_custkey = o_custkey
//     AND o_orderkey = l_orderkey
// GROUP BY
//     c_name,
//     c_custkey,
//     o_orderkey,
//     o_orderdate,
//     o_totalprice
// ORDER BY
//     o_totalprice DESC,
//     o_orderdate
// LIMIT 100;
#[tokio::test]
async fn tpch_q18_prove_verify() {
    let spec = query_spec(18);
    println!("TPCH Q18 SQL:\n{}", spec.sql);
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

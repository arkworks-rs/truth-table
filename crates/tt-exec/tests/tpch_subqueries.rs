#![cfg(feature = "test-utils")]

//! TPC-H queries whose scalar subqueries DataFusion decorrelates into LEFT
//! joins under a filter that rejects NULLs; the planner turns them into
//! INNER joins, which the join protocols prove.

async fn prove(number: u8) {
    let spec = tpch_data::query_spec(number, false);
    tt_exec::test_utils::prove_and_verify_query(spec.sql, spec.tables, None)
        .await
        .unwrap_or_else(|err| panic!("TPC-H q{number}: {err}"));
}

#[tokio::test]
async fn tpch_q2() {
    prove(2).await;
}

#[tokio::test]
async fn tpch_q17() {
    prove(17).await;
}

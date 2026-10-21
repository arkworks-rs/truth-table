#![cfg(feature = "test-utils")]

//! The Poneglyph variants of the benchmark list's TPC-H queries, in a
//! process of their own (see `tpch.rs`).

async fn prove(number: u8) {
    let spec = tpch_data::query_spec(number, true);
    tt_exec::test_utils::prove_and_verify_query(spec.sql, spec.tables, None)
        .await
        .unwrap_or_else(|err| panic!("TPC-H q{number} (Poneglyph): {err:?}"));
}

#[tokio::test]
async fn tpch_q01() {
    prove(1).await;
}

#[tokio::test]
async fn tpch_q03() {
    prove(3).await;
}

#[tokio::test]
async fn tpch_q05() {
    prove(5).await;
}

#[tokio::test]
async fn tpch_q08() {
    prove(8).await;
}

#[tokio::test]
async fn tpch_q09() {
    prove(9).await;
}

#[tokio::test]
async fn tpch_q18() {
    prove(18).await;
}

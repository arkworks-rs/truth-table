#![cfg(feature = "test-utils")]

//! Every TPC-H query of the benchmark list, proved and verified on the test
//! tables. The Poneglyph variants are in `tpch_poneglyph.rs`: fingerprint
//! rules are per process and keyed by column name, and `orders` and
//! `orders_poneglyph` give `o_clerk` different rules.

async fn prove(number: u8) {
    let spec = tpch_data::query_spec(number, false);
    tt_exec::test_utils::prove_and_verify_query(spec.sql, spec.tables, None)
        .await
        .unwrap_or_else(|err| panic!("TPC-H q{number}: {err:?}"));
}

#[tokio::test]
async fn tpch_q01() {
    prove(1).await;
}

#[tokio::test]
async fn tpch_q02() {
    prove(2).await;
}

#[tokio::test]
async fn tpch_q03() {
    prove(3).await;
}

#[tokio::test]
async fn tpch_q04() {
    prove(4).await;
}

#[tokio::test]
async fn tpch_q05() {
    prove(5).await;
}

#[tokio::test]
async fn tpch_q06() {
    prove(6).await;
}

#[tokio::test]
async fn tpch_q07() {
    prove(7).await;
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
async fn tpch_q10() {
    prove(10).await;
}

#[tokio::test]
async fn tpch_q12() {
    prove(12).await;
}

#[tokio::test]
async fn tpch_q14() {
    prove(14).await;
}

#[tokio::test]
async fn tpch_q15() {
    prove(15).await;
}

#[tokio::test]
async fn tpch_q17() {
    prove(17).await;
}

#[tokio::test]
async fn tpch_q18() {
    prove(18).await;
}

#[tokio::test]
async fn tpch_q19() {
    prove(19).await;
}

#[tokio::test]
async fn tpch_q20() {
    prove(20).await;
}

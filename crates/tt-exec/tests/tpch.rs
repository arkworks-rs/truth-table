#![cfg(feature = "test-utils")]

//! TPC-H queries from the benchmark list, proved and verified on the test
//! tables. The Poneglyph variants need their own committed tables.

async fn prove(number: u8) {
    let spec = tpch_data::query_spec(number, false);
    tt_exec::test_utils::prove_and_verify_query(spec.sql, spec.tables, None)
        .await
        .unwrap_or_else(|err| panic!("TPC-H q{number}: {err}"));
}

/// A composite foreign key (lineitem into partsupp) must give prover and
/// verifier the same join mode.
#[tokio::test]
async fn tpch_q9() {
    prove(9).await;
}

/// The subquery scans every lineitem column: the verifier must not see a
/// string's `__length` segment as a column of its own.
#[tokio::test]
async fn tpch_q18() {
    prove(18).await;
}

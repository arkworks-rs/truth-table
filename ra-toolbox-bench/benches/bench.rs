mod group_by;
mod select;

use arithmetic::table::{ArithTable, df_to_table};
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    prover::Prover,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::prelude::SessionContext;

type P = PST13<Bls12_381>;
type K = KZG10<Bls12_381>;
type F = Fr;

const MAX_LOG_VAR: usize = 23;

async fn prepare_table(query: &str, prover: &mut Prover<F, P, K>) -> ArithTable<F, P, K> {
    exec_custom_query(query, prover, true).await
}

async fn exec_custom_query(
    query: &str,
    prover: &mut Prover<F, P, K>,
    compute_actvtr: bool,
) -> ArithTable<F, P, K> {
    let ctx = SessionContext::new().enable_url_table();

    let df = ctx.sql(query).await.unwrap();

    df_to_table(prover, df, MAX_LOG_VAR, compute_actvtr)
        .await
        .unwrap()
}

fn main() {
    divan::main()
}

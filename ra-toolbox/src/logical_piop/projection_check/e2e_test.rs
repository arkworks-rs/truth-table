use super::*;

use crate::dispatch_piop;

use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    prover::Prover,
    test_utils::test_prelude,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::prelude::{ParquetReadOptions, SessionContext};
use planner::{
    arithmetized_plan::ArithmetizedTree, ra_proof_plan::logical_to_proof_plan,
    witness_plan::HintTree,
};
use std::sync::Arc;
use tpch_data::test_data_path;

type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;

#[tokio::test]
#[ignore]
async fn projection_plan_dispatches_piop() {
    let (mut prover, _verifier): (Prover<F, MvPCS, UvPCS>, _) = test_prelude().unwrap();
    let ctx = SessionContext::new();

    let parquet_path = test_data_path("lineitem.parquet");
    assert!(
        parquet_path.exists(),
        "Missing Parquet at {:?}",
        parquet_path
    );

    ctx.register_parquet(
        "lineitem",
        parquet_path.to_str().expect("parquet path should be valid"),
        ParquetReadOptions::default(),
    )
    .await
    .unwrap();

    let sql = "SELECT l_orderkey FROM lineitem";
    let df = ctx.sql(sql).await.unwrap();
    let logical = df.into_unoptimized_plan();

    let proof_plan = logical_to_proof_plan(&ctx, &logical);
    let witness_plan = HintTree::from_proof_plan(&ctx, Arc::clone(&proof_plan))
        .await
        .unwrap();
    let arithmetized_plan = ArithmetizedTree::from_witness_plan(witness_plan, &mut prover).unwrap();

    dispatch_piop(&mut prover, &proof_plan, &arithmetized_plan);
}

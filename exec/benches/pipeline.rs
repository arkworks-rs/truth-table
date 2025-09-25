#![allow(clippy::needless_borrows_for_generic_args)]

use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    test_utils::bench_prelude,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::prelude::{ParquetReadOptions, SessionContext};
use planner::{
    arithmetized_plan::ArithmetizedPlan, ra_proof_plan::logical_to_proof_plan,
    witness_plan::WitnessPlan,
};

#[divan::bench(
    args = [
        // Simple projection+filter+limit over TPCH customer parquet
        "SELECT c_custkey FROM customer",
        // Another projection with predicate
        "SELECT c_name FROM customer",
    ]
)]
fn plan_pipeline(sql: &str) {
    // Create a multi-thread runtime once per-bench
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        let (mut prover, mut verifier) =
            bench_prelude::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>().unwrap();
        let ctx = SessionContext::new();
        let customer_parquet = tpch_data::bench_data_path("customer.parquet");
        assert!(
            customer_parquet.exists(),
            "Missing bench-data at {} — generate with gen_bench_data",
            customer_parquet.display()
        );
        ctx.register_parquet(
            "customer",
            customer_parquet.to_str().unwrap(),
            ParquetReadOptions::default(),
        )
        .await
        .expect("register customer parquet");

        // 1) Parse SQL to logical plan
        let df = ctx.sql(sql).await.expect("sql parse");
        let logical = df.into_unoptimized_plan();

        // 2) Logical -> ProofPlan
        let proof_plan = logical_to_proof_plan(&ctx, &logical);

        // 3) ProofPlan -> WitnessPlan (parallel execution of witness plans)
        let witness_plan = WitnessPlan::from_proof_plan(&ctx, proof_plan)
            .await
            .expect("witness tree");
        // 4) WitnessPlan -> ArithmetizedPlan
        let arithmetized_plan =
            ArithmetizedPlan::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>::from_witness_plan(
                witness_plan,
                &mut prover,
            )
            .expect("arithmetize plan");
    });
}

fn main() {
    // Run benches
    divan::main();
}

use super::*;
use ark_piop::pcs::{kzg10::KZG10, pst13::PST13};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::{
    arrow::{
        array::{ArrayRef, Int32Array},
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    },
    prelude::SessionContext,
};
use std::sync::Arc;

#[tokio::test]
async fn builds_proof_tree_from_simple_query() {
    let schema = Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::Int32,
        false,
    )]));

    let batch = RecordBatch::try_new(
        schema,
        vec![Arc::new(Int32Array::from(vec![1, 2, 3])) as ArrayRef],
    )
    .unwrap();

    let ctx = SessionContext::new();
    ctx.register_batch("dummy_table", batch).unwrap();

    let df = ctx
        .sql("SELECT value FROM dummy_table")
        .await
        .unwrap();
    let plan = df.into_unoptimized_plan();
    let shared_ctx: SharedCtx<Fr, PST13<Bls12_381>, KZG10<Bls12_381>> = SharedCtx::default();
    let proof_tree = ProverProofTree::from_lp(&ctx, shared_ctx, &plan, &None);
    println!("{}", proof_tree.graphviz_display());
}

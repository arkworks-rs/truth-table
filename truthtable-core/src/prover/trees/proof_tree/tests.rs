use super::*;
use crate::tree::Tree;
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

async fn build_proof_tree_for_query(
    query: &str,
) -> ProverProofTree<Fr, PST13<Bls12_381>, KZG10<Bls12_381>> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("value", DataType::Int32, false),
        Field::new("flag", DataType::Int32, false),
    ]));

    let batch = RecordBatch::try_new(
        schema,
        vec![
            Arc::new(Int32Array::from(vec![1, 2, 3, 3])) as ArrayRef,
            Arc::new(Int32Array::from(vec![0, 1, 1, 0])) as ArrayRef,
        ],
    )
    .unwrap();

    let ctx = SessionContext::new();
    ctx.register_batch("dummy_table", batch).unwrap();

    let df = ctx.sql(query).await.unwrap();
    let plan = df.into_unoptimized_plan();
    let shared_ctx: SharedCtx<Fr, PST13<Bls12_381>, KZG10<Bls12_381>> = SharedCtx::default();
    ProverProofTree::from_lp(&ctx, shared_ctx, &plan, &None)
}

#[tokio::test]
async fn builds_projection_proof_tree_from_simple_query() {
    let proof_tree = build_proof_tree_for_query("SELECT value FROM dummy_table").await;
    println!("{}", proof_tree.display_graphviz());
}
#[tokio::test]
async fn builds_filter_proof_tree_from_simple_query() {
    let proof_tree =
        build_proof_tree_for_query("SELECT value FROM dummy_table WHERE flag > 0").await;
    println!("{}", proof_tree.display_graphviz());
}

#[tokio::test]
async fn builds_aggregate_proof_tree_from_simple_query() {
    let proof_tree =
        build_proof_tree_for_query("SELECT value, COUNT(*) AS cnt FROM dummy_table GROUP BY value")
            .await;
    println!("{}", proof_tree.display_graphviz());
}

use std::sync::Arc;

use super::ProverArithmetizedTree;
use crate::{
    prover_trees::{hint_tree::ProverHintTree, proof_tree::ProverProofTree},
    test_utils::test_df_plan,
};
use arithmetic::ctx::SharedCtx;
use ark_piop::pcs::{kzg10::KZG10, pst13::PST13};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::{
    arrow::{
        array::Int32Array,
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    },
    prelude::SessionContext,
};

type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;

#[tokio::test]
async fn from_hint_tree_produces_serializable_tables() {
    let ctx = SessionContext::new();
    let plan = test_df_plan(
        &ctx,
        "SELECT l_orderkey FROM lineitem WHERE l_quantity >= l_suppkey",
        "lineitem",
    )
    .await
    .unwrap();
    let prover_ctx = SharedCtx::default();
    let proof_tree: ProverProofTree<F, MvPCS, UvPCS> =
        ProverProofTree::from_lp(&ctx, prover_ctx, &plan);
    let hint_tree = ProverHintTree::from_proof_tree(&ctx, proof_tree)
        .await
        .unwrap();

    let arith_tree = ProverArithmetizedTree::<F, MvPCS, UvPCS>::from_hint_tree(hint_tree).unwrap();
    assert!(arith_tree.len() > 0);

    let (_proof_tree, tables) = arith_tree.into_parts();
    assert!(!tables.is_empty());
    for table_map in tables.values() {
        for table in table_map.values() {
            if table.size() > 0 {
                assert!(table.size().is_power_of_two());
            }
            assert_eq!(table.num_total_cols(), table.data_polys().len());
        }
    }
}

#[test]
fn arith_table_from_batches_empty() {
    let table =
        ProverArithmetizedTree::<F, MvPCS, UvPCS>::arith_table_from_batches(Vec::new()).unwrap();
    assert_eq!(table.size(), 0);
    assert_eq!(table.num_total_cols(), 0);
    assert!(table.schema().is_none());
}

#[test]
fn arith_table_from_batches_basic() {
    let schema = Arc::new(Schema::new(vec![Field::new("col", DataType::Int32, false)]));
    let data = Arc::new(Int32Array::from(vec![1, 2, 3, 4])) as Arc<_>;
    let batch = RecordBatch::try_new(schema.clone(), vec![data]).unwrap();

    let table =
        ProverArithmetizedTree::<F, MvPCS, UvPCS>::arith_table_from_batches(vec![batch]).unwrap();

    assert_eq!(table.size(), 4);
    assert_eq!(table.num_total_cols(), 1);
    let (field_ref, mle) = &table.data_polys()[0];
    assert_eq!(field_ref.name(), "col");
    assert_eq!(mle.evaluations().len(), 4);
}

#[tokio::test]
#[ignore = "This test is for visualization purposes and may require manual inspection."]
async fn display_graphviz() {
    let ctx = SessionContext::new();
    let plan = test_df_plan(
        &ctx,
        "SELECT l_orderkey FROM lineitem WHERE l_quantity >= l_suppkey",
        "lineitem",
    )
    .await
    .unwrap();
    let prover_ctx = SharedCtx::default();
    let proof_tree: ProverProofTree<F, MvPCS, UvPCS> =
        ProverProofTree::from_lp(&ctx, prover_ctx, &plan);
    let hint_tree = ProverHintTree::from_proof_tree(&ctx, proof_tree)
        .await
        .unwrap();
    let arith_tree = ProverArithmetizedTree::from_hint_tree(hint_tree).unwrap();

    println!("{}", arith_tree.display_graphviz());
}

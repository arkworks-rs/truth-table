use crate::proof_tree;

use super::ProofTree;
use ark_piop::pcs::{kzg10::KZG10, pst13::PST13};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::{
    error::Result as DFResult,
    logical_expr::LogicalPlan,
    prelude::{ParquetReadOptions, SessionContext},
};
use tpch_data::test_data_path;

async fn build_plan(ctx: &SessionContext) -> DFResult<LogicalPlan> {
    let parquet_path = test_data_path("lineitem.parquet");
    assert!(
        parquet_path.exists(),
        "Missing Parquet at {:?}",
        parquet_path
    );

    ctx.register_parquet(
        "lineitem",
        parquet_path
            .to_str()
            .expect("parquet path should be valid UTF-8"),
        ParquetReadOptions::default(),
    )
    .await?;

    let sql = "SELECT l_orderkey FROM lineitem WHERE l_quantity >= 10";
    let df = ctx.sql(sql).await?;
    Ok(df.into_unoptimized_plan())
}

#[tokio::test]
#[ignore]
async fn display_graphviz() {
    let ctx = SessionContext::new();
    let plan = build_plan(&ctx).await.unwrap();
    let proof_tree: ProofTree<Fr, PST13<Bls12_381>, KZG10<Bls12_381>> =
        ProofTree::from_logical_plan(&ctx, &plan);
    let flattened = proof_tree.flatten();
    assert!(!flattened.is_empty());
    assert!(flattened.contains_key(&proof_tree.root_ref().node_id()));
    println!("{}", proof_tree.display_graphviz());
}

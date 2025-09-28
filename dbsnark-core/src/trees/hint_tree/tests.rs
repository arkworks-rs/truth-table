use super::HintTree;
use crate::trees::proof_tree::ProofTree;
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
async fn display_graphviz_smoke() -> DFResult<()> {
    let ctx = SessionContext::new();
    let plan = build_plan(&ctx).await?;
    let proof_tree = ProofTree::from_logical_plan(&ctx, &plan);
    let hint_tree = HintTree::from_proof_tree(&ctx, proof_tree).await?;

    println!("{}", hint_tree.display_graphviz());
    Ok(())
}

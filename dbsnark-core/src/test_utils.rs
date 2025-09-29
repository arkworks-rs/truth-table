use datafusion::{
    error::{Result, Result as DFResult},
    logical_expr::LogicalPlan,
    prelude::{ParquetReadOptions, SessionContext},
};
use tpch_data::test_data_path;
pub async fn test_df_plan(ctx: &SessionContext) -> DFResult<LogicalPlan> {
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

    let sql = "SELECT l_orderkey FROM lineitem WHERE l_quantity >= l_suppkey";
    let df = ctx.sql(sql).await?;
    Ok(df.into_unoptimized_plan())
}

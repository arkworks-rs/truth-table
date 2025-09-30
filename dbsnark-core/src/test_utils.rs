use datafusion::{
    error::{Result, Result as DFResult},
    logical_expr::LogicalPlan,
    prelude::{ParquetReadOptions, SessionContext},
};
use tpch_data::test_data_path;
pub async fn test_df_plan(
    ctx: &SessionContext,
    query: &str,
    table_name: &str,
) -> DFResult<LogicalPlan> {
    let parquet_path = test_data_path(&format!("{}.parquet", table_name));
    assert!(
        parquet_path.exists(),
        "Missing Parquet at {:?}",
        parquet_path
    );

    ctx.register_parquet(
        table_name,
        parquet_path
            .to_str()
            .expect("parquet path should be valid UTF-8"),
        ParquetReadOptions::default(),
    )
    .await?;

    let df = ctx.sql(&query).await?;
    Ok(df.into_unoptimized_plan())
}

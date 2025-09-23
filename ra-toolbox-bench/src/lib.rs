use std::path::PathBuf;

use datafusion::logical_expr::{Expr, LogicalPlan};

#[tokio::test]
async fn test_setup() -> Result<(), Box<dyn std::error::Error>> {
    use datafusion::prelude::*;

    let ctx = SessionContext::new();

    // Use output path to ensure compatibility
    let path: PathBuf = std::env::current_dir()?.join("parquets/title-sanitized.parquet");

    // Register or query using full path
    ctx.register_parquet(
        "titles",
        path.to_str().unwrap(),
        ParquetReadOptions::default(),
    )
    .await?;
    let df = ctx
        .sql("SELECT PRODUCTION_YEAR, ID FROM titles where production_year = 2000 AND id = 1")
        .await?;

    let logical_plan = df.logical_plan();
    if let LogicalPlan::Projection(projection) = &logical_plan {
        if let LogicalPlan::Filter(filter) = &*projection.input.clone() {
            println!("Filter: {:#?}", filter);
        }
    }

    Ok(())
}

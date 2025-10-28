use std::sync::Arc;

use datafusion::{
    error::Result as DFResult,
    logical_expr::LogicalPlan,
    optimizer::{Optimizer, OptimizerContext, OptimizerRule},
    prelude::{ParquetReadOptions, SessionContext},
};
use tpch_data::test_data_path;
pub async fn test_df_plan(
    ctx: &SessionContext,
    query: &str,
    table_names: &[&str],
) -> DFResult<LogicalPlan> {
    for &table_name in table_names {
        let parquet_path = test_data_path(&format!("{table_name}.parquet"));
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
    }
    let state = ctx.state();
    let mut plan = state.create_logical_plan(query).await?;
    let rules: Vec<Arc<dyn OptimizerRule + Send + Sync>> = vec![];

    let optimizer = Optimizer::with_rules(rules);

    let config = OptimizerContext::new().with_max_passes(16);

    let plan = optimizer.optimize(plan.clone(), &config, observer)?;

    fn observer(plan: &LogicalPlan, rule: &dyn OptimizerRule) {
        println!(
            "After applying rule '{}':\n{}",
            rule.name(),
            plan.display_indent()
        )
    }
    Ok(plan)
}

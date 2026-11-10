//! Drops the system columns (`__row_id__`, `__activator__`) from every
//! projection. The parquet tables carry them, so `SELECT *` lists them; but
//! every node carries them on its own, outside its data columns, and a node
//! that projects them as data finds them nowhere. Runs after wildcard
//! expansion, on prover and verifier alike.

use arithmetic::is_system_column;
use datafusion::{config::ConfigOptions, optimizer::analyzer::AnalyzerRule};
use datafusion_common::{
    Result,
    tree_node::{Transformed, TreeNode},
};
use datafusion_expr::{
    Expr,
    logical_plan::{LogicalPlan, Projection},
};

#[derive(Debug, Default)]
pub(crate) struct HideSystemColumns;

impl HideSystemColumns {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl AnalyzerRule for HideSystemColumns {
    fn name(&self) -> &str {
        "hide_system_columns"
    }

    fn analyze(&self, plan: LogicalPlan, _config: &ConfigOptions) -> Result<LogicalPlan> {
        plan.transform_up(|plan| match plan {
            LogicalPlan::Projection(projection)
                if projection.expr.iter().any(is_system_column_ref) =>
            {
                let kept: Vec<Expr> = projection
                    .expr
                    .into_iter()
                    .filter(|expr| !is_system_column_ref(expr))
                    .collect();
                Ok(Transformed::yes(LogicalPlan::Projection(
                    Projection::try_new(kept, projection.input)?,
                )))
            }
            // A parent keeps the schema it was built with; a child that lost
            // columns needs it rebuilt.
            other => Ok(Transformed::yes(other.recompute_schema()?)),
        })
        .map(|transformed| transformed.data)
    }
}

fn is_system_column_ref(expr: &Expr) -> bool {
    match expr {
        Expr::Column(column) => is_system_column(&column.name),
        Expr::Alias(alias) => is_system_column_ref(&alias.expr),
        _ => false,
    }
}

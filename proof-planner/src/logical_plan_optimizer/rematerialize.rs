use datafusion::{
    dataframe::DataFrame,
    execution::context::SessionState,
    optimizer::{ApplyOrder, OptimizerConfig, OptimizerRule},
};
use datafusion_common::{
    tree_node::{Transformed, TreeNode, TreeNodeRecursion},
    Column, DataFusionError, Result as DataFusionResult,
};
use datafusion_expr::{Expr, LogicalPlan};
use tokio::runtime::RuntimeFlavor;
use tt_core::irs::nodes::plan::rematerialize::{
    RematerializeLogicalNode, wrap_logical_plan,
};

#[derive(Debug)]
pub struct RematerializeRule {
    session_state: SessionState,
}

impl RematerializeRule {
    pub fn new(session_state: SessionState) -> Self {
        Self { session_state }
    }
}

impl OptimizerRule for RematerializeRule {
    fn name(&self) -> &str {
        "rematerialize"
    }

    fn apply_order(&self) -> Option<ApplyOrder> {
        Some(ApplyOrder::TopDown)
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        _config: &dyn OptimizerConfig,
    ) -> DataFusionResult<Transformed<LogicalPlan>> {
        let transformed = plan.transform_down(|node| {
            let is_rematerialize_extension = matches!(
                &node,
                LogicalPlan::Extension(extension)
                    if extension.node.as_any().is::<RematerializeLogicalNode>()
            );
            if is_rematerialize_extension {
                return Ok(Transformed::new(node, false, TreeNodeRecursion::Stop));
            }

            match node {
                LogicalPlan::Filter(filter) => {
                    let input_plan = filter.input.as_ref().clone();
                    let filtered_plan = LogicalPlan::Filter(filter.clone());
                    let total_rows = row_count(&self.session_state, &input_plan)?;
                    if total_rows == 0 {
                        return Ok(Transformed::no(filtered_plan));
                    }
                    let active_rows = row_count(&self.session_state, &filtered_plan)?;
                    if active_rows * 2 <= total_rows {
                        Ok(Transformed::new(
                            wrap_logical_plan(filtered_plan),
                            true,
                            TreeNodeRecursion::Stop,
                        ))
                    } else {
                        Ok(Transformed::no(filtered_plan))
                    }
                }
                _ => Ok(Transformed::no(node)),
            }
        })?;

        if transformed.transformed {
            let plan = strip_unresolvable_qualifiers(transformed.data)?;
            return Ok(Transformed::yes(plan));
        }

        Ok(transformed)
    }
}

fn row_count(session_state: &SessionState, plan: &LogicalPlan) -> DataFusionResult<usize> {
    let df = DataFrame::new(session_state.clone(), plan.clone());
    let batches = collect_blocking(df)?;
    Ok(batches.iter().map(|batch| batch.num_rows()).sum())
}

fn collect_blocking(df: DataFrame) -> DataFusionResult<Vec<datafusion::arrow::record_batch::RecordBatch>> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => match handle.runtime_flavor() {
            RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(df.collect()))
            }
            RuntimeFlavor::CurrentThread => {
                let df_clone = df.clone();
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| DataFusionError::Execution(e.to_string()))?;
                    rt.block_on(df_clone.collect())
                })
                .join()
                .map_err(|_| {
                    DataFusionError::Execution("rematerialize collect thread panicked".to_string())
                })?
            }
            _ => tokio::task::block_in_place(|| handle.block_on(df.collect())),
        },
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| DataFusionError::Execution(e.to_string()))?;
            rt.block_on(df.collect())
        }
    }
}

fn strip_unresolvable_qualifiers(plan: LogicalPlan) -> DataFusionResult<LogicalPlan> {
    let transformed = plan.transform_down(|node| {
        let qualifiers: Vec<_> = node
            .schema()
            .iter()
            .filter_map(|(qualifier, _)| qualifier.cloned())
            .collect();
        node.map_expressions(|expr| {
            expr.transform(|inner| {
                if let Expr::Column(col) = &inner {
                    if let Some(relation) = col.relation.as_ref() {
                        if !qualifiers.iter().any(|q| q == relation) {
                            return Ok(Transformed::yes(Expr::Column(
                                Column::new_unqualified(col.name.clone()),
                            )));
                        }
                    }
                }
                Ok(Transformed::no(inner))
            })
        })
    })?;
    Ok(transformed.data)
}

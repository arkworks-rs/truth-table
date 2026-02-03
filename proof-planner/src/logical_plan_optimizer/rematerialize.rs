use datafusion::{
    dataframe::DataFrame,
    execution::context::SessionState,
    optimizer::{ApplyOrder, OptimizerConfig, OptimizerRule},
};
use datafusion_common::{
    tree_node::{Transformed, TreeNode, TreeNodeRecursion},
    DataFusionError, Result as DataFusionResult,
};
use datafusion_expr::LogicalPlan;
use tokio::runtime::RuntimeFlavor;
use tt_core::irs::nodes::plan::rematerialize::{wrap_logical_plan, RematerializeLogicalNode};

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
                    let a = next_power_of_two_strict(total_rows);
                    let b = next_power_of_two_strict(active_rows);
                    if b < a {
                        Ok(Transformed::new(
                            wrap_logical_plan(filtered_plan),
                            true,
                            TreeNodeRecursion::Stop,
                        ))
                    } else {
                        Ok(Transformed::no(filtered_plan))
                    }
                }
                LogicalPlan::Aggregate(aggregate) => {
                    let input_plan = aggregate.input.as_ref().clone();
                    let aggregate_plan = LogicalPlan::Aggregate(aggregate.clone());
                    let total_rows = row_count(&self.session_state, &input_plan)?;
                    if total_rows == 0 {
                        return Ok(Transformed::no(aggregate_plan));
                    }
                    let output_rows = row_count(&self.session_state, &aggregate_plan)?;
                    let a = next_power_of_two_strict(total_rows);
                    let b = next_power_of_two_strict(output_rows);
                    if b < a {
                        Ok(Transformed::new(
                            wrap_logical_plan(aggregate_plan),
                            true,
                            TreeNodeRecursion::Stop,
                        ))
                    } else {
                        Ok(Transformed::no(aggregate_plan))
                    }
                }
                _ => Ok(Transformed::no(node)),
            }
        })?;

        Ok(transformed)
    }
}

fn row_count(session_state: &SessionState, plan: &LogicalPlan) -> DataFusionResult<usize> {
    let plan = strip_rematerialize(plan)?;
    let df = DataFrame::new(session_state.clone(), plan);
    let batches = collect_blocking(df)?;
    Ok(batches.iter().map(|batch| batch.num_rows()).sum())
}

fn strip_rematerialize(plan: &LogicalPlan) -> DataFusionResult<LogicalPlan> {
    let transformed = plan.clone().transform_down(|node| {
        let LogicalPlan::Extension(extension) = &node else {
            return Ok(Transformed::no(node));
        };
        if !extension.node.as_any().is::<RematerializeLogicalNode>() {
            return Ok(Transformed::no(node));
        }
        let remat = extension
            .node
            .as_any()
            .downcast_ref::<RematerializeLogicalNode>()
            .expect("rematerialize extension node");
        Ok(Transformed::new(
            remat.input().clone(),
            true,
            TreeNodeRecursion::Continue,
        ))
    })?;
    Ok(transformed.data)
}

fn next_power_of_two_strict(value: usize) -> usize {
    if value <= 1 {
        return 2.min(1.max(value + 1));
    }
    if value.is_power_of_two() {
        value.saturating_mul(2)
    } else {
        value.next_power_of_two()
    }
}

fn collect_blocking(
    df: DataFrame,
) -> DataFusionResult<Vec<datafusion::arrow::record_batch::RecordBatch>> {
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

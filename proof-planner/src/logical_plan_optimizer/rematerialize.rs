use datafusion::{
    dataframe::DataFrame,
    execution::context::SessionState,
    optimizer::{ApplyOrder, OptimizerConfig, OptimizerRule},
    prelude::SessionContext,
};
use datafusion_common::{
    tree_node::{Transformed, TreeNode, TreeNodeRecursion},
    DataFusionError, Result as DataFusionResult,
};
use datafusion_expr::LogicalPlan;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use tokio::runtime::RuntimeFlavor;
use tt_core::irs::nodes::plan::rematerialize::{wrap_logical_plan, RematerializeLogicalNode};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationHints {
    pub hints: Vec<OptimizationHint>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OptimizationHint {
    Rematerialize { target_path: Vec<usize> },
}

impl OptimizationHints {
    pub fn is_empty(&self) -> bool {
        self.hints.is_empty()
    }
}

pub fn collect_data_dependent_hints(
    session_ctx: &SessionContext,
    plan: &LogicalPlan,
) -> DataFusionResult<OptimizationHints> {
    // The prover is the only side allowed to inspect data-dependent row counts.
    let mut hints = Vec::new();
    let mut path = Vec::new();
    collect_rematerialize_hints(&session_ctx.state(), plan, &mut path, &mut hints)?;
    Ok(OptimizationHints { hints })
}

pub fn apply_optimization_hints(
    plan: LogicalPlan,
    hints: &OptimizationHints,
) -> DataFusionResult<LogicalPlan> {
    // The verifier rebuilds the plan from the trusted query, then replays only
    // these narrow structural decisions from the prover.
    let mut remat_paths = hints
        .hints
        .iter()
        .map(|hint| match hint {
            OptimizationHint::Rematerialize { target_path } => target_path.clone(),
        })
        .collect::<BTreeSet<_>>();
    let mut path = Vec::new();
    let rewritten = apply_rematerialize_hints(plan, &mut path, &mut remat_paths)?;
    if !remat_paths.is_empty() {
        return Err(DataFusionError::Plan(format!(
            "Unapplied optimization hints at paths: {:?}",
            remat_paths
        )));
    }
    Ok(rewritten)
}

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
                LogicalPlan::Join(join) => {
                    let join_plan = LogicalPlan::Join(join.clone());
                    let left_rows = row_count(&self.session_state, &join.left)?;
                    let right_rows = row_count(&self.session_state, &join.right)?;
                    let hypercube_size = next_power_of_two_strict(left_rows.max(right_rows));
                    if hypercube_size == 0 {
                        return Ok(Transformed::no(join_plan));
                    }
                    let active_rows = row_count(&self.session_state, &join_plan)?;
                    if active_rows.saturating_mul(2) < hypercube_size {
                        Ok(Transformed::new(
                            wrap_logical_plan(join_plan),
                            true,
                            TreeNodeRecursion::Stop,
                        ))
                    } else {
                        Ok(Transformed::no(join_plan))
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

fn collect_rematerialize_hints(
    session_state: &SessionState,
    plan: &LogicalPlan,
    path: &mut Vec<usize>,
    hints: &mut Vec<OptimizationHint>,
) -> DataFusionResult<()> {
    if should_rematerialize(session_state, plan)? {
        hints.push(OptimizationHint::Rematerialize {
            target_path: path.clone(),
        });
        return Ok(());
    }

    for (idx, input) in plan.inputs().into_iter().enumerate() {
        path.push(idx);
        collect_rematerialize_hints(session_state, input, path, hints)?;
        path.pop();
    }
    Ok(())
}

fn apply_rematerialize_hints(
    plan: LogicalPlan,
    path: &mut Vec<usize>,
    remaining_paths: &mut BTreeSet<Vec<usize>>,
) -> DataFusionResult<LogicalPlan> {
    if remaining_paths.remove(path) {
        ensure_rematerialize_target(&plan, path)?;
        return Ok(wrap_logical_plan(plan));
    }

    let new_inputs = plan
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(idx, input)| {
            path.push(idx);
            let rewritten = apply_rematerialize_hints(input.clone(), path, remaining_paths);
            path.pop();
            rewritten
        })
        .collect::<DataFusionResult<Vec<_>>>()?;
    plan.with_new_exprs(plan.expressions(), new_inputs)
}

fn ensure_rematerialize_target(plan: &LogicalPlan, path: &[usize]) -> DataFusionResult<()> {
    if supports_rematerialize(plan) {
        return Ok(());
    }
    Err(DataFusionError::Plan(format!(
        "Rematerialize hint cannot be applied at path {:?} to plan node {}",
        path,
        plan.display()
    )))
}

fn supports_rematerialize(plan: &LogicalPlan) -> bool {
    matches!(
        plan,
        LogicalPlan::Filter(_) | LogicalPlan::Aggregate(_) | LogicalPlan::Join(_)
    )
}

fn should_rematerialize(
    session_state: &SessionState,
    plan: &LogicalPlan,
) -> DataFusionResult<bool> {
    let is_rematerialize_extension = matches!(
        plan,
        LogicalPlan::Extension(extension)
            if extension.node.as_any().is::<RematerializeLogicalNode>()
    );
    if is_rematerialize_extension {
        return Ok(false);
    }

    match plan {
        LogicalPlan::Filter(filter) => {
            let input_plan = filter.input.as_ref().clone();
            let filtered_plan = LogicalPlan::Filter(filter.clone());
            let total_rows = row_count(session_state, &input_plan)?;
            if total_rows == 0 {
                return Ok(false);
            }
            let active_rows = row_count(session_state, &filtered_plan)?;
            let a = next_power_of_two_strict(total_rows);
            let b = next_power_of_two_strict(active_rows);
            Ok(b < a)
        }
        LogicalPlan::Aggregate(aggregate) => {
            let input_plan = aggregate.input.as_ref().clone();
            let aggregate_plan = LogicalPlan::Aggregate(aggregate.clone());
            let total_rows = row_count(session_state, &input_plan)?;
            if total_rows == 0 {
                return Ok(false);
            }
            let output_rows = row_count(session_state, &aggregate_plan)?;
            let a = next_power_of_two_strict(total_rows);
            let b = next_power_of_two_strict(output_rows);
            Ok(b < a)
        }
        LogicalPlan::Join(join) => {
            let join_plan = LogicalPlan::Join(join.clone());
            let left_rows = row_count(session_state, &join.left)?;
            let right_rows = row_count(session_state, &join.right)?;
            let hypercube_size = next_power_of_two_strict(left_rows.max(right_rows));
            if hypercube_size == 0 {
                return Ok(false);
            }
            let active_rows = row_count(session_state, &join_plan)?;
            Ok(active_rows.saturating_mul(2) < hypercube_size)
        }
        _ => Ok(false),
    }
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

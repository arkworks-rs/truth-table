use std::collections::BTreeSet;
use std::sync::Arc;

use datafusion::dataframe::DataFrame;
use datafusion::execution::context::SessionState;
use datafusion::prelude::SessionContext;
use datafusion_common::{
    DataFusionError, Result as DataFusionResult,
    tree_node::{Transformed, TreeNode, TreeNodeRecursion},
};
use datafusion_expr::LogicalPlan;
use serde::{Deserialize, Serialize};
use tokio::runtime::RuntimeFlavor;
use tt_core::irs::nodes::plan::rematerialize::RematerializeLogicalNode;

mod rematerialize;
mod truncate_empty_payload;
pub use rematerialize::RematerializeRule;
pub use truncate_empty_payload::TruncateEmptyPayloadRule;

/// Verifier-replayable data-dependent optimization decisions. Each rule's
/// hints map to exactly one variant; `apply_optimization_hints` dispatches
/// per-variant to the rule's apply path.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OptimizationHint {
    /// Wrap the LP subtree at `target_path` in a `RematerializeLogicalNode`.
    Rematerialize { target_path: Vec<usize> },
    /// Replace the LP subtree at `target_path` with an `EmptyRelation`
    /// carrying the original subtree's schema. Emitted by
    /// [`TruncateEmptyPayloadRule`] when the prover observes that the
    /// subtree's output is empty.
    Truncate { target_path: Vec<usize> },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationHints {
    pub hints: Vec<OptimizationHint>,
}

impl OptimizationHints {
    pub fn is_empty(&self) -> bool {
        self.hints.is_empty()
    }
}

/// A data-dependent logical-plan optimization.
///
/// Parallel to DataFusion's `OptimizerRule`, but the result is a set of
/// `OptimizationHint`s rather than a rewritten plan. Hints are emitted by the
/// prover (which can see row counts) and shipped with the proof so the verifier
/// can replay the same structural choice without re-running the data-dependent
/// analysis.
pub trait DataDependentOptimizationRule: Send + Sync {
    /// Stable identifier for this rule (used for diagnostics and rule filtering).
    fn name(&self) -> &str;

    /// Walk the analyzed-and-structurally-optimized plan and produce any hints
    /// this rule wants the verifier to replay.
    fn collect_hints(
        &self,
        session_state: &SessionState,
        plan: &LogicalPlan,
    ) -> DataFusionResult<Vec<OptimizationHint>>;
}

/// Runs a configured set of `DataDependentOptimizationRule`s over a plan and
/// merges their hints into a single `OptimizationHints` payload.
pub struct DataDependentOptimizer {
    rules: Vec<Arc<dyn DataDependentOptimizationRule>>,
}

impl DataDependentOptimizer {
    /// Build an optimizer that runs the given rules in order.
    pub fn with_rules(rules: Vec<Arc<dyn DataDependentOptimizationRule>>) -> Self {
        Self { rules }
    }

    /// Borrow the rule list (useful for filtering, e.g. benchmarks that ablate
    /// individual rules).
    pub fn rules(&self) -> &[Arc<dyn DataDependentOptimizationRule>] {
        &self.rules
    }

    /// Run every rule against `plan` and return their merged hint set.
    pub fn collect_hints(
        &self,
        session_ctx: &SessionContext,
        plan: &LogicalPlan,
    ) -> DataFusionResult<OptimizationHints> {
        let state = session_ctx.state();
        let mut hints = Vec::new();
        for rule in &self.rules {
            hints.extend(rule.collect_hints(&state, plan)?);
        }
        Ok(OptimizationHints { hints })
    }
}

/// Default set of data-dependent rules used by the production prover and data
/// owner. Benchmarks (or other callers) may construct a `DataDependentOptimizer`
/// from a filtered subset of this list to disable specific rules.
pub fn rules() -> Vec<Arc<dyn DataDependentOptimizationRule>> {
    // `TruncateEmptyPayloadRule` is available but not included here; callers
    // that want it can construct a `DataDependentOptimizer` with an extended
    // rule list.
    vec![Arc::new(RematerializeRule::new())]
}

/// Production entry point: run the default `DataDependentOptimizer` over the
/// plan. Callers that need a filtered rule set (e.g. ablation benchmarks)
/// should construct a `DataDependentOptimizer` directly via
/// [`DataDependentOptimizer::with_rules`].
pub fn collect_data_dependent_hints(
    session_ctx: &SessionContext,
    plan: &LogicalPlan,
) -> DataFusionResult<OptimizationHints> {
    DataDependentOptimizer::with_rules(rules()).collect_hints(session_ctx, plan)
}

/// Apply every collected hint to the plan, dispatching per-variant.
///
/// Truncate hints run first (they may eliminate entire subtrees, removing
/// rematerialize targets that no longer need wrapping). Rematerialize hints
/// run on whatever subtrees remain.
pub fn apply_optimization_hints(
    plan: LogicalPlan,
    hints: &OptimizationHints,
) -> DataFusionResult<LogicalPlan> {
    if hints.hints.is_empty() {
        // No hints means nothing to do — skip the walk entirely to avoid the
        // round-trip through with_new_exprs, which subtly changes Join nodes
        // even when they shouldn't be touched.
        return Ok(plan);
    }

    let mut remat_paths: BTreeSet<Vec<usize>> = BTreeSet::new();
    let mut truncate_paths: BTreeSet<Vec<usize>> = BTreeSet::new();
    for hint in &hints.hints {
        match hint {
            OptimizationHint::Rematerialize { target_path } => {
                remat_paths.insert(target_path.clone());
            }
            OptimizationHint::Truncate { target_path } => {
                truncate_paths.insert(target_path.clone());
            }
        }
    }

    let plan = if truncate_paths.is_empty() {
        plan
    } else {
        let mut path = Vec::new();
        let rewritten =
            truncate_empty_payload::apply_truncate_hints(plan, &mut path, &mut truncate_paths)?;
        if !truncate_paths.is_empty() {
            return Err(DataFusionError::Plan(format!(
                "Unapplied truncate hints at paths: {:?}",
                truncate_paths
            )));
        }
        rewritten
    };

    if remat_paths.is_empty() {
        return Ok(plan);
    }
    let mut path = Vec::new();
    let rewritten = rematerialize::apply_rematerialize_hints(plan, &mut path, &mut remat_paths)?;
    if !remat_paths.is_empty() {
        return Err(DataFusionError::Plan(format!(
            "Unapplied rematerialize hints at paths: {:?}",
            remat_paths
        )));
    }
    Ok(rewritten)
}

// ── Shared utilities for data-dependent rules ──────────────────────────────

/// Count the rows produced by `plan` by executing it through DataFusion.
/// Pre-existing rematerialize wrappers are stripped first so the row count
/// reflects the underlying plan, not the wrapper layer.
pub(crate) fn row_count(
    session_state: &SessionState,
    plan: &LogicalPlan,
) -> DataFusionResult<usize> {
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
                    DataFusionError::Execution(
                        "data-dependent rule collect thread panicked".to_string(),
                    )
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

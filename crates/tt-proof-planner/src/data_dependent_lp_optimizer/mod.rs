use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use arithmetic::fingerprint::Bin;
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
use tt_core::irs::nodes::plan::compaction::CompactionLogicalNode;

mod compaction;
mod prefilter_bins;
mod truncate_empty_payload;
pub use compaction::CompactionRule;
pub use prefilter_bins::PrefilterBinsRule;
pub use truncate_empty_payload::TruncateEmptyPayloadRule;

/// Verifier-replayable data-dependent optimization decisions. Each rule's
/// hints map to exactly one variant; `apply_optimization_hints` dispatches
/// per-variant to the rule's apply path.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OptimizationHint {
    /// Set the bins the fingerprint pre-filter at `target_path` tests, or
    /// remove it when `bins` is empty. Emitted by [`PrefilterBinsRule`]
    /// from the prover's greedy choice; the verifier checks the bins are the
    /// pattern's.
    PrefilterBins {
        target_path: Vec<usize>,
        bins: Vec<Bin>,
    },
    /// Wrap the LP subtree at `target_path` in a `CompactionLogicalNode`.
    Compaction { target_path: Vec<usize> },
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

    /// Run every rule in order and return their merged hint set. Each rule
    /// sees the plan with the earlier rules' hints applied, so a later
    /// decision (e.g. compacting after a pre-filter) reflects the
    /// earlier ones; [`apply_optimization_hints`] applies the variants in the
    /// same order, so the verifier rebuilds the same plan.
    pub fn collect_hints(
        &self,
        session_ctx: &SessionContext,
        plan: &LogicalPlan,
    ) -> DataFusionResult<OptimizationHints> {
        let state = session_ctx.state();
        let mut hints = Vec::new();
        let mut current = plan.clone();
        for rule in &self.rules {
            let rule_hints = OptimizationHints {
                hints: rule.collect_hints(&state, &current)?,
            };
            current = apply_optimization_hints(current, &rule_hints)?;
            hints.extend(rule_hints.hints);
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
    // rule list. Pre-filter bin counts come first: compaction decisions
    // depend on how much the pre-filters drop.
    vec![
        Arc::new(PrefilterBinsRule::new()),
        Arc::new(CompactionRule::new()),
    ]
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
/// Pre-filter bin counts run first (they may remove a pre-filter, which
/// shifts the paths below it, and compaction hints were collected on the
/// plan after them). Truncate hints run next (they may eliminate entire
/// subtrees, removing compaction targets that no longer need wrapping).
/// Compaction hints run on whatever subtrees remain.
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

    let mut compaction_paths: BTreeSet<Vec<usize>> = BTreeSet::new();
    let mut truncate_paths: BTreeSet<Vec<usize>> = BTreeSet::new();
    let mut prefilter_bins: BTreeMap<Vec<usize>, Vec<Bin>> = BTreeMap::new();
    for hint in &hints.hints {
        match hint {
            OptimizationHint::PrefilterBins { target_path, bins } => {
                prefilter_bins.insert(target_path.clone(), bins.clone());
            }
            OptimizationHint::Compaction { target_path } => {
                compaction_paths.insert(target_path.clone());
            }
            OptimizationHint::Truncate { target_path } => {
                truncate_paths.insert(target_path.clone());
            }
        }
    }

    let plan = if prefilter_bins.is_empty() {
        plan
    } else {
        let mut path = Vec::new();
        let rewritten =
            prefilter_bins::apply_prefilter_bins_hints(plan, &mut path, &mut prefilter_bins)?;
        if !prefilter_bins.is_empty() {
            return Err(DataFusionError::Plan(format!(
                "Unapplied pre-filter bin hints at paths: {:?}",
                prefilter_bins.keys().collect::<Vec<_>>()
            )));
        }
        rewritten
    };

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

    if compaction_paths.is_empty() {
        return Ok(plan);
    }
    let mut path = Vec::new();
    let rewritten = compaction::apply_compaction_hints(plan, &mut path, &mut compaction_paths)?;
    if !compaction_paths.is_empty() {
        return Err(DataFusionError::Plan(format!(
            "Unapplied compaction hints at paths: {:?}",
            compaction_paths
        )));
    }
    Ok(rewritten)
}

// ── Shared utilities for data-dependent rules ──────────────────────────────

/// Count the rows produced by `plan` by executing it through DataFusion.
/// Pre-existing compaction wrappers are stripped first so the row count
/// reflects the underlying plan, not the wrapper layer.
pub(crate) fn row_count(
    session_state: &SessionState,
    plan: &LogicalPlan,
) -> DataFusionResult<usize> {
    let plan = strip_compaction(plan)?;
    let df = DataFrame::new(session_state.clone(), plan);
    let batches = collect_blocking(df)?;
    Ok(batches.iter().map(|batch| batch.num_rows()).sum())
}

fn strip_compaction(plan: &LogicalPlan) -> DataFusionResult<LogicalPlan> {
    let transformed = plan.clone().transform_down(|node| {
        let LogicalPlan::Extension(extension) = &node else {
            return Ok(Transformed::no(node));
        };
        if !extension.node.as_any().is::<CompactionLogicalNode>() {
            return Ok(Transformed::no(node));
        }
        let compaction = extension
            .node
            .as_any()
            .downcast_ref::<CompactionLogicalNode>()
            .expect("compaction extension node");
        Ok(Transformed::new(
            compaction.input().clone(),
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

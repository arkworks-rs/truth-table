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
use tt_core::irs::nodes::plan::compaction::CompactionLogicalNode;

mod compaction;
mod prefilter_bins;
mod truncate_empty_payload;
pub use compaction::CompactionRule;
pub use prefilter_bins::PrefilterBinsRule;
pub use truncate_empty_payload::TruncateEmptyPayloadRule;

/// A data-dependent decision the verifier replays. Each rule emits one
/// variant.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OptimizationHint {
    /// Set the bins the fingerprint pre-filter at `target_path` tests, or
    /// remove it when `bins` is empty. The verifier checks the bins are among
    /// the pattern's.
    PrefilterBins {
        target_path: Vec<usize>,
        bins: Vec<Bin>,
    },
    /// Wrap the LP subtree at `target_path` in a `CompactionLogicalNode`.
    Compaction { target_path: Vec<usize> },
    /// Replace the LP subtree at `target_path`, whose output is empty, with
    /// an `EmptyRelation` of the same schema.
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

/// A data-dependent logical-plan optimization. Unlike DataFusion's
/// `OptimizerRule` it returns `OptimizationHint`s instead of a rewritten plan:
/// the prover, who sees row counts, ships them with the proof and the verifier
/// replays them.
pub trait DataDependentOptimizationRule: Send + Sync {
    /// Stable identifier, used for diagnostics and rule filtering.
    fn name(&self) -> &str;

    /// `plan` is the analyzed and structurally optimized plan.
    fn collect_hints(
        &self,
        session_state: &SessionState,
        plan: &LogicalPlan,
    ) -> DataFusionResult<Vec<OptimizationHint>>;
}

pub struct DataDependentOptimizer {
    rules: Vec<Arc<dyn DataDependentOptimizationRule>>,
}

impl DataDependentOptimizer {
    pub fn with_rules(rules: Vec<Arc<dyn DataDependentOptimizationRule>>) -> Self {
        Self { rules }
    }

    /// For filtering, e.g. benchmarks that ablate individual rules.
    pub fn rules(&self) -> &[Arc<dyn DataDependentOptimizationRule>] {
        &self.rules
    }

    /// Each rule sees the plan with the earlier rules' hints applied, so a
    /// later decision (compacting after a pre-filter) reflects the earlier
    /// ones. [`apply_optimization_hints`] applies the variants in the same
    /// order, so the verifier rebuilds the same plan.
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

/// The default rules of the prover and data owner. Benchmarks build a
/// `DataDependentOptimizer` from a subset to disable specific rules.
pub fn rules() -> Vec<Arc<dyn DataDependentOptimizationRule>> {
    // `TruncateEmptyPayloadRule` is not in the default list. The pre-filter
    // rule comes first: compaction decisions depend on how much the
    // pre-filters drop.
    vec![
        Arc::new(PrefilterBinsRule::new()),
        Arc::new(CompactionRule::new()),
    ]
}

/// Collects hints with the default [`rules`].
pub fn collect_data_dependent_hints(
    session_ctx: &SessionContext,
    plan: &LogicalPlan,
) -> DataFusionResult<OptimizationHints> {
    DataDependentOptimizer::with_rules(rules()).collect_hints(session_ctx, plan)
}

/// Applies the hints by variant, in this order:
/// 1. pre-filter bins: removing a pre-filter shifts the paths below it, and
///    compaction hints were collected on the plan after these;
/// 2. truncation: it can remove subtrees that hold compaction targets;
/// 3. compaction, on the subtrees that remain.
pub fn apply_optimization_hints(
    plan: LogicalPlan,
    hints: &OptimizationHints,
) -> DataFusionResult<LogicalPlan> {
    if hints.hints.is_empty() {
        // Skip the walk: the round-trip through `with_new_exprs` changes Join
        // nodes even when no hint targets them.
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

/// Counts the rows `plan` produces by executing it through DataFusion, with
/// compaction wrappers stripped.
pub(crate) fn row_count(
    session_state: &SessionState,
    plan: &LogicalPlan,
) -> DataFusionResult<usize> {
    let plan = strip_compaction(plan)?;
    let df = DataFrame::new(session_state.clone(), plan);
    let batches = tt_core::session::block_on(df.collect())?;
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

use std::collections::BTreeSet;
use std::sync::Arc;

use datafusion::execution::context::SessionState;
use datafusion_common::Result as DataFusionResult;
use datafusion_expr::{EmptyRelation, LogicalPlan};

use super::{DataDependentOptimizationRule, OptimizationHint, row_count};

/// Emits a `Truncate` hint for every LP subtree whose runtime output is
/// empty. The verifier replaces the subtree with an `EmptyRelation` of the
/// same schema, and DataFusion's `PropagateEmptyRelation` then simplifies the
/// surrounding plan. Not in the default `data_dependent_lp_optimizer::rules()`.
#[derive(Debug, Default)]
pub struct TruncateEmptyPayloadRule;

impl TruncateEmptyPayloadRule {
    pub fn new() -> Self {
        Self
    }
}

impl DataDependentOptimizationRule for TruncateEmptyPayloadRule {
    fn name(&self) -> &str {
        "truncate_empty_payload"
    }

    fn collect_hints(
        &self,
        session_state: &SessionState,
        plan: &LogicalPlan,
    ) -> DataFusionResult<Vec<OptimizationHint>> {
        let mut hints = Vec::new();
        let mut path = Vec::new();
        collect_truncate_hints(session_state, plan, &mut path, &mut hints)?;
        Ok(hints)
    }
}

fn collect_truncate_hints(
    session_state: &SessionState,
    plan: &LogicalPlan,
    path: &mut Vec<usize>,
    hints: &mut Vec<OptimizationHint>,
) -> DataFusionResult<()> {
    if matches!(plan, LogicalPlan::EmptyRelation(_)) {
        return Ok(());
    }
    if row_count(session_state, plan)? == 0 {
        hints.push(OptimizationHint::Truncate {
            target_path: path.clone(),
        });
        // Do not descend: a deeper hint would target a discarded path.
        return Ok(());
    }
    for (idx, input) in plan.inputs().into_iter().enumerate() {
        path.push(idx);
        collect_truncate_hints(session_state, input, path, hints)?;
        path.pop();
    }
    Ok(())
}

pub(super) fn apply_truncate_hints(
    plan: LogicalPlan,
    path: &mut Vec<usize>,
    remaining_paths: &mut BTreeSet<Vec<usize>>,
) -> DataFusionResult<LogicalPlan> {
    if remaining_paths.remove(path) {
        let schema = Arc::clone(plan.schema());
        return Ok(LogicalPlan::EmptyRelation(EmptyRelation {
            produce_one_row: false,
            schema,
        }));
    }
    let new_inputs = plan
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(idx, input)| {
            path.push(idx);
            let rewritten = apply_truncate_hints(input.clone(), path, remaining_paths);
            path.pop();
            rewritten
        })
        .collect::<DataFusionResult<Vec<_>>>()?;
    plan.with_new_exprs(plan.expressions(), new_inputs)
}

use datafusion::execution::context::SessionState;
use datafusion_common::{DataFusionError, Result as DataFusionResult};
use datafusion_expr::{BinaryExpr, Expr, LogicalPlan, Operator};
use std::collections::BTreeSet;
use tt_core::irs::nodes::plan::{
    rematerialize::{RematerializeLogicalNode, wrap_logical_plan},
    result_check::ResultCheckLogicalNode,
};

use super::{DataDependentOptimizationRule, OptimizationHint, row_count};

/// Data-dependent rule that wraps Filter / Aggregate nodes in a
/// `RematerializeLogicalNode` whenever the node's output row count fits in
/// a strictly smaller power-of-two hypercube than its input. Limit is
/// excluded because wrapping it triggers prover-side `FalseClaim` panics on
/// queries with explicit `LIMIT` (Q3, Q10).
#[derive(Debug, Default)]
pub struct RematerializeRule;

impl RematerializeRule {
    pub fn new() -> Self {
        Self
    }
}

impl DataDependentOptimizationRule for RematerializeRule {
    fn name(&self) -> &str {
        "rematerialize"
    }

    fn collect_hints(
        &self,
        session_state: &SessionState,
        plan: &LogicalPlan,
    ) -> DataFusionResult<Vec<OptimizationHint>> {
        let mut hints = Vec::new();
        let mut path = Vec::new();
        collect_rematerialize_hints(session_state, plan, false, &mut path, &mut hints)?;
        Ok(hints)
    }
}

fn collect_rematerialize_hints(
    session_state: &SessionState,
    plan: &LogicalPlan,
    parent_is_result_check: bool,
    path: &mut Vec<usize>,
    hints: &mut Vec<OptimizationHint>,
) -> DataFusionResult<()> {
    if !parent_is_result_check && should_rematerialize(session_state, plan)? {
        hints.push(OptimizationHint::Rematerialize {
            target_path: path.clone(),
        });
        return Ok(());
    }

    let child_parent_is_result_check = is_result_check_plan(plan);

    for (idx, input) in plan.inputs().into_iter().enumerate() {
        path.push(idx);
        collect_rematerialize_hints(
            session_state,
            input,
            child_parent_is_result_check,
            path,
            hints,
        )?;
        path.pop();
    }
    Ok(())
}

pub(super) fn apply_rematerialize_hints(
    plan: LogicalPlan,
    path: &mut Vec<usize>,
    remaining_paths: &mut BTreeSet<Vec<usize>>,
) -> DataFusionResult<LogicalPlan> {
    apply_rematerialize_hints_with_result_check_guard(plan, path, remaining_paths, false)
}

fn apply_rematerialize_hints_with_result_check_guard(
    plan: LogicalPlan,
    path: &mut Vec<usize>,
    remaining_paths: &mut BTreeSet<Vec<usize>>,
    parent_is_result_check: bool,
) -> DataFusionResult<LogicalPlan> {
    let was_hit = remaining_paths.remove(path);

    // Match `collect_rematerialize_hints`: only the immediate child of a
    // `ResultCheck` is in the tail; the flag does not propagate through
    // Sort / Projection / SubqueryAlias.
    let child_parent_is_result_check = is_result_check_plan(&plan);

    // Post-order: rewrite children first so nested hints wrap before we
    // (optionally) wrap the current node. Without this, an outer wrap would
    // return early and skip any deeper hints in the same branch.
    let new_inputs = plan
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(idx, input)| {
            path.push(idx);
            let rewritten = apply_rematerialize_hints_with_result_check_guard(
                input.clone(),
                path,
                remaining_paths,
                child_parent_is_result_check,
            );
            path.pop();
            rewritten
        })
        .collect::<DataFusionResult<Vec<_>>>()?;
    let rewritten = plan.with_new_exprs(expressions_for_with_new_exprs(&plan), new_inputs)?;

    if was_hit {
        if parent_is_result_check {
            return Ok(rewritten);
        }
        ensure_rematerialize_target(&rewritten, path)?;
        Ok(wrap_logical_plan(rewritten))
    } else {
        Ok(rewritten)
    }
}

/// Rebuild the `Vec<Expr>` argument that `LogicalPlan::with_new_exprs` expects.
///
/// `plan.expressions()` flattens `Join.on: Vec<(Expr, Expr)>` into
/// `[left_0, right_0, left_1, right_1, ...]`, but `with_new_exprs` for Join
/// requires each equi-expr to be a `BinaryExpr(left = right)`. Feeding the
/// flattened form back in loses pairs and triggers
/// `"The front part expressions should be an binary equality expression"`
/// inside DataFusion. Rebuild the equality-wrapped form here so the
/// round-trip is a true no-op.
fn expressions_for_with_new_exprs(plan: &LogicalPlan) -> Vec<Expr> {
    if let LogicalPlan::Join(join) = plan {
        let mut exprs: Vec<Expr> = join
            .on
            .iter()
            .map(|(left, right)| {
                Expr::BinaryExpr(BinaryExpr::new(
                    Box::new(left.clone()),
                    Operator::Eq,
                    Box::new(right.clone()),
                ))
            })
            .collect();
        if let Some(filter) = &join.filter {
            exprs.push(filter.clone());
        }
        return exprs;
    }
    plan.expressions()
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
    // Limit is excluded: wrapping a Limit in Rematerialize triggers
    // `HonestProverError(FalseClaim)` on queries with explicit LIMIT (Q3, Q10).
    // Needs an IR-side investigation before re-enabling.
    matches!(plan, LogicalPlan::Filter(_) | LogicalPlan::Aggregate(_))
}

fn is_result_check_plan(plan: &LogicalPlan) -> bool {
    matches!(
        plan,
        LogicalPlan::Extension(extension)
            if extension.node.as_any().is::<ResultCheckLogicalNode>()
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

    let hypercube_halves =
        |input_plan: &LogicalPlan, op_plan: &LogicalPlan| -> DataFusionResult<bool> {
            let input_active = row_count(session_state, input_plan)?;
            if input_active == 0 {
                return Ok(false);
            }
            let output_active = row_count(session_state, op_plan)?;
            Ok(next_power_of_two_strict(output_active) < next_power_of_two_strict(input_active))
        };

    match plan {
        LogicalPlan::Filter(filter) => {
            hypercube_halves(filter.input.as_ref(), &LogicalPlan::Filter(filter.clone()))
        }
        LogicalPlan::Aggregate(aggregate) => hypercube_halves(
            aggregate.input.as_ref(),
            &LogicalPlan::Aggregate(aggregate.clone()),
        ),
        _ => Ok(false),
    }
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


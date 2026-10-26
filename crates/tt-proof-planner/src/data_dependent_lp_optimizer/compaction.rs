use datafusion::execution::context::SessionState;
use datafusion_common::{DataFusionError, Result as DataFusionResult, tree_node::TreeNode};
use datafusion_expr::{BinaryExpr, Expr, LogicalPlan, Operator};
use std::collections::BTreeSet;
use tt_core::irs::{
    nodes::plan::{
        compaction::{CompactionLogicalNode, wrap_logical_plan},
        result_check::ResultCheckLogicalNode,
    },
    string_order::{StringOrder, string_order},
};

use super::{DataDependentOptimizationRule, OptimizationHint, row_count};

/// Wraps a Filter or Aggregate in a `CompactionLogicalNode` when its output
/// fits a strictly smaller power-of-two hypercube than its input, unless the
/// node is in the result tail (only Projections and SubqueryAliases between
/// it and the `ResultCheck`). Those operators do no per-row proof work and
/// the result check's multiset argument takes the node's own domain, so
/// compacting there (a row permutation plus a char-domain DPUC over every
/// column, the projected-away ones included) only adds cost.
#[derive(Debug, Default)]
pub struct CompactionRule;

impl CompactionRule {
    pub fn new() -> Self {
        Self
    }
}

impl DataDependentOptimizationRule for CompactionRule {
    fn name(&self) -> &str {
        "compaction"
    }

    fn collect_hints(
        &self,
        session_state: &SessionState,
        plan: &LogicalPlan,
    ) -> DataFusionResult<Vec<OptimizationHint>> {
        // A compaction re-encodes characters that only its DPUC binds, and
        // only for a single side column; the lexicographic string order reads
        // characters at the ORDER BY, so it forbids compaction altogether.
        if string_order() == StringOrder::Lexicographic {
            return Ok(Vec::new());
        }
        let mut hints = Vec::new();
        let mut path = Vec::new();
        collect_compaction_hints(session_state, plan, false, &mut path, &mut hints)?;
        Ok(hints)
    }
}

fn collect_compaction_hints(
    session_state: &SessionState,
    plan: &LogicalPlan,
    in_result_tail: bool,
    path: &mut Vec<usize>,
    hints: &mut Vec<OptimizationHint>,
) -> DataFusionResult<()> {
    if !in_result_tail && !follows_order_by(plan)? && should_compact(session_state, plan)? {
        hints.push(OptimizationHint::Compaction {
            target_path: path.clone(),
        });
        // Keep walking: stacked shrinking filters (the LIKE pre-filter under
        // its LIKE filter) each get their own wrap. Row counts come from the
        // original plan, so a hint above does not change the decision below.
    }

    let child_in_result_tail = child_in_result_tail(plan, in_result_tail);

    for (idx, input) in plan.inputs().into_iter().enumerate() {
        path.push(idx);
        collect_compaction_hints(session_state, input, child_in_result_tail, path, hints)?;
        path.pop();
    }
    Ok(())
}

pub(super) fn apply_compaction_hints(
    plan: LogicalPlan,
    path: &mut Vec<usize>,
    remaining_paths: &mut BTreeSet<Vec<usize>>,
) -> DataFusionResult<LogicalPlan> {
    apply_compaction_hints_with_result_check_guard(plan, path, remaining_paths, false)
}

fn apply_compaction_hints_with_result_check_guard(
    plan: LogicalPlan,
    path: &mut Vec<usize>,
    remaining_paths: &mut BTreeSet<Vec<usize>>,
    in_result_tail: bool,
) -> DataFusionResult<LogicalPlan> {
    let was_hit = remaining_paths.remove(path);

    // Match `collect_compaction_hints`, so a hint collected elsewhere
    // (an older proof, a different rule set) can never wrap a tail node.
    let child_in_result_tail = child_in_result_tail(&plan, in_result_tail);

    // Post-order: children are rewritten before the current node is wrapped,
    // so nested hints in the same branch are all applied.
    let new_inputs = plan
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(idx, input)| {
            path.push(idx);
            let rewritten = apply_compaction_hints_with_result_check_guard(
                input.clone(),
                path,
                remaining_paths,
                child_in_result_tail,
            );
            path.pop();
            rewritten
        })
        .collect::<DataFusionResult<Vec<_>>>()?;
    let rewritten = plan.with_new_exprs(expressions_for_with_new_exprs(&plan), new_inputs)?;

    if was_hit {
        if in_result_tail {
            return Ok(rewritten);
        }
        ensure_compaction_target(&rewritten, path)?;
        Ok(wrap_logical_plan(rewritten))
    } else {
        Ok(rewritten)
    }
}

/// The `Vec<Expr>` that `LogicalPlan::with_new_exprs` expects. For a Join,
/// `plan.expressions()` flattens `on` into `[left_0, right_0, left_1, ...]`
/// while `with_new_exprs` requires one `left = right` equality per pair and
/// errors on the flattened form, so the equalities are rebuilt here.
pub(super) fn expressions_for_with_new_exprs(plan: &LogicalPlan) -> Vec<Expr> {
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

fn ensure_compaction_target(plan: &LogicalPlan, path: &[usize]) -> DataFusionResult<()> {
    if follows_order_by(plan)? {
        return Err(DataFusionError::Plan(format!(
            "Compaction hint at path {:?} follows an ORDER BY: {}",
            path,
            plan.display()
        )));
    }
    // TODO: Limit is excluded because wrapping it in Compaction triggers
    // `HonestProverError(FalseClaim)` on queries with an explicit LIMIT
    // (TPC-H Q3, Q10). Needs an IR-side investigation.
    if matches!(plan, LogicalPlan::Filter(_) | LogicalPlan::Aggregate(_)) {
        return Ok(());
    }
    Err(DataFusionError::Plan(format!(
        "Compaction hint cannot be applied at path {:?} to plan node {}",
        path,
        plan.display()
    )))
}

/// Whether an ORDER BY runs below `plan`. Compaction proves only that its
/// output holds its input's rows, not in which order, so the paper forbids
/// it after an ORDER BY (PIOP 20): the planner never places one there and
/// the verifier rejects a hint that does.
fn follows_order_by(plan: &LogicalPlan) -> DataFusionResult<bool> {
    for input in plan.inputs() {
        if input.exists(|node| Ok(matches!(node, LogicalPlan::Sort(_))))? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `plan`'s inputs are in the result tail: `plan` is the
/// `ResultCheck` itself, or is in the tail and passes rows through
/// untouched. Sort, Aggregate, Join and Limit all read every row of their
/// input, so the tail ends at them.
fn child_in_result_tail(plan: &LogicalPlan, in_result_tail: bool) -> bool {
    is_result_check_plan(plan)
        || (in_result_tail
            && matches!(
                plan,
                LogicalPlan::Projection(_) | LogicalPlan::SubqueryAlias(_)
            ))
}

fn is_result_check_plan(plan: &LogicalPlan) -> bool {
    matches!(
        plan,
        LogicalPlan::Extension(extension)
            if extension.node.as_any().is::<ResultCheckLogicalNode>()
    )
}

fn should_compact(session_state: &SessionState, plan: &LogicalPlan) -> DataFusionResult<bool> {
    let is_compaction_extension = matches!(
        plan,
        LogicalPlan::Extension(extension)
            if extension.node.as_any().is::<CompactionLogicalNode>()
    );
    if is_compaction_extension {
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion_expr::{LogicalPlan, col, lit, logical_plan::table_scan};

    use super::apply_compaction_hints;

    fn scan() -> datafusion_expr::LogicalPlanBuilder {
        let schema = Schema::new(vec![
            Field::new("k", DataType::Int64, false),
            Field::new("v", DataType::Int64, false),
        ]);
        table_scan(Some("t"), &schema, None).unwrap()
    }

    fn compact_root(plan: LogicalPlan) -> datafusion_common::Result<LogicalPlan> {
        let mut remaining = BTreeSet::from([vec![]]);
        apply_compaction_hints(plan, &mut Vec::new(), &mut remaining)
    }

    #[test]
    fn a_filter_may_be_compacted() {
        let plan = scan().filter(col("v").eq(lit(1))).unwrap().build().unwrap();
        assert!(compact_root(plan).is_ok());
    }

    #[test]
    fn a_compaction_hint_after_an_order_by_is_rejected() {
        let plan = scan()
            .sort(vec![col("k").sort(true, false)])
            .unwrap()
            .limit(0, Some(3))
            .unwrap()
            .filter(col("v").eq(lit(1)))
            .unwrap()
            .build()
            .unwrap();
        assert!(compact_root(plan).is_err());
    }
}

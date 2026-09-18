use datafusion::execution::context::SessionState;
use datafusion_common::{
    DataFusionError, Result as DataFusionResult,
    tree_node::{TreeNode, TreeNodeRecursion},
};
use datafusion_expr::{BinaryExpr, Distinct, Expr, LogicalPlan, Operator};
use std::collections::BTreeSet;
use tt_core::irs::nodes::plan::{
    rematerialize::{RematerializeLogicalNode, wrap_logical_plan},
    result_check::ResultCheckLogicalNode,
};

use super::{DataDependentOptimizationRule, OptimizationHint, row_count};

#[cfg(test)]
mod tests;

/// Data-dependent rule that wraps Filter / Aggregate nodes in a
/// `RematerializeLogicalNode` whenever the node's output row count fits in
/// a strictly smaller power-of-two hypercube than its input.
///
/// Rematerialization currently proves bag equality, not order preservation.
/// Until an order-demand analysis or a stable compaction check is available,
/// this rule declines all plans containing Sort, Limit (including a limit
/// pushed into `TableScan.fetch`), Window, DISTINCT ON, explicitly ordered
/// expressions, or an unknown extension node. This is deliberately
/// conservative: compaction below a subsequent Sort can be safe, and SQL LIMIT
/// without ORDER BY does not promise a particular global order.
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
        if contains_order_sensitive_operator(plan)? {
            return Ok(Vec::new());
        }
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
    // Hints are prover-supplied. Recheck the same structural restriction on
    // the verifier path; suppressing only honest collection is insufficient.
    if !remaining_paths.is_empty() {
        ensure_rematerialization_is_order_safe(&plan)?;
    }
    apply_rematerialize_hints_with_result_check_guard(plan, path, remaining_paths, false)
}

/// Reject bag-only rematerialization whenever the original plan has an
/// order-dependent operator. Call this before applying any other untrusted
/// rewrite, since such a rewrite could erase the node that carries the order
/// demand and thereby bypass a later structural check.
pub(super) fn ensure_rematerialization_is_order_safe(plan: &LogicalPlan) -> DataFusionResult<()> {
    if contains_order_sensitive_operator(plan)? {
        return Err(DataFusionError::Plan(
            "Rematerialize hints are not supported for plans containing Sort, Limit (including a pushed-down TableScan fetch), Window, DISTINCT ON, an explicitly ordered expression, or an unknown extension node: bag equality does not preserve order".to_string(),
        ));
    }
    Ok(())
}

/// Detect order-sensitive constructs through wrappers and expression
/// subqueries. Both hint collection and replay use this conservative
/// whole-plan policy. This is an allowlist: plan variants outside the query
/// fragment currently lowered by TruthTable fail closed, as do unknown
/// extension nodes. Only TruthTable's two audited identity wrappers are
/// admitted.
fn contains_order_sensitive_operator(plan: &LogicalPlan) -> DataFusionResult<bool> {
    let mut found = false;
    plan.apply_with_subqueries(|node| {
        let is_order_sensitive = match node {
            LogicalPlan::Projection(_)
            | LogicalPlan::Filter(_)
            | LogicalPlan::Aggregate(_)
            | LogicalPlan::Join(_)
            | LogicalPlan::SubqueryAlias(_) => false,
            LogicalPlan::TableScan(scan) => scan.fetch.is_some(),
            LogicalPlan::Extension(extension) => {
                !is_result_check_plan(node)
                    && !extension.node.as_any().is::<RematerializeLogicalNode>()
            }
            LogicalPlan::Sort(_)
            | LogicalPlan::Limit(_)
            | LogicalPlan::Window(_)
            | LogicalPlan::Distinct(Distinct::On(_)) => true,
            // These variants are not part of the currently audited lowering
            // fragment (some, such as Repartition and Union, may also alter
            // physical order). Treat them as unsafe until reviewed.
            _ => true,
        };
        if is_order_sensitive || contains_explicit_ordering(node)? {
            found = true;
            Ok(TreeNodeRecursion::Stop)
        } else {
            Ok(TreeNodeRecursion::Continue)
        }
    })?;
    Ok(found)
}

/// Some order requirements live inside expressions rather than in a Sort
/// node. In particular, SQL aggregates may carry their own ORDER BY clause.
/// Window expressions are included defensively even though DataFusion normally
/// places them in a `LogicalPlan::Window`, which is already rejected above.
fn contains_explicit_ordering(plan: &LogicalPlan) -> DataFusionResult<bool> {
    let mut found = false;
    for expression in plan.expressions() {
        expression.apply(|nested| {
            let ordered = match nested {
                Expr::AggregateFunction(function) => function
                    .params
                    .order_by
                    .as_ref()
                    .is_some_and(|order_by| !order_by.is_empty()),
                Expr::WindowFunction(function) => !function.params.order_by.is_empty(),
                _ => false,
            };
            if ordered {
                found = true;
                Ok(TreeNodeRecursion::Stop)
            } else {
                Ok(TreeNodeRecursion::Continue)
            }
        })?;
        if found {
            break;
        }
    }
    Ok(found)
}

fn apply_rematerialize_hints_with_result_check_guard(
    plan: LogicalPlan,
    path: &mut Vec<usize>,
    remaining_paths: &mut BTreeSet<Vec<usize>>,
    parent_is_result_check: bool,
) -> DataFusionResult<LogicalPlan> {
    let was_hit = remaining_paths.remove(path);

    // Match `collect_rematerialize_hints`: only the immediate child of a
    // `ResultCheck` is in the tail. The separate whole-plan order guard above
    // already excludes order-sensitive operators, including under wrappers.
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

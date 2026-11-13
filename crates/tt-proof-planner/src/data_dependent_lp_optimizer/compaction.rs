use datafusion::execution::context::SessionState;
use datafusion_common::{DataFusionError, Result as DataFusionResult, tree_node::TreeNode};
use datafusion_expr::{BinaryExpr, Expr, LogicalPlan, Operator};
use std::collections::BTreeSet;
use tt_core::irs::{
    nodes::plan::{
        compaction::{CompactionLogicalNode, wrap_logical_plan},
        exprs::fp_prefilter::prefilter_args,
        result_check::ResultCheckLogicalNode,
    },
    string_order::{StringOrder, string_order},
};

use super::{
    DataDependentOptimizationRule, OptimizationHint, proved_empty::is_proved_empty, row_count,
};

/// Wraps a Filter or Aggregate in a `CompactionLogicalNode` when its output
/// fits a hypercube at least `MIN_SHRINK` times smaller than its input's
/// (a filter on string characters: any strictly smaller one), unless the
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
    if is_proved_empty(plan) {
        // Compacting the witness would permute rows nothing above reads.
        let witness = plan.inputs()[0];
        path.push(0);
        for (idx, input) in witness.inputs().into_iter().enumerate() {
            path.push(idx);
            collect_compaction_hints(session_state, input, false, path, hints)?;
            path.pop();
        }
        path.pop();
        return Ok(());
    }
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

    let (input, reads_chars) = match plan {
        LogicalPlan::Filter(filter) => (
            filter.input.as_ref(),
            filter.predicate.exists(|expr| {
                Ok(matches!(expr, Expr::Like(_)) || prefilter_args(expr).is_some())
            })?,
        ),
        LogicalPlan::Aggregate(aggregate) => (aggregate.input.as_ref(), false),
        _ => return Ok(false),
    };
    let input_rows = row_count(session_state, input)?;
    if input_rows == 0 {
        return Ok(false);
    }
    let output_rows = row_count(session_state, plan)?;
    if reads_chars {
        // The LIKE cost model (`arithmetic::fingerprint::cost`) prices the
        // pre-filter's bins assuming exactly this test.
        return Ok(next_power_of_two_strict(output_rows) < next_power_of_two_strict(input_rows));
    }
    // A padded scan's rows are its domain; any other input's rows round up to
    // a lower bound on its domain, so every compaction shrinks by MIN_SHRINK.
    Ok(output_rows
        .max(1)
        .next_power_of_two()
        .saturating_mul(MIN_SHRINK)
        <= input_rows.next_power_of_two())
}

/// The least factor by which a compaction must shrink the domain. Its
/// permutation check commits dense helpers over the whole input domain, which
/// the work above repays only on a much smaller domain.
const MIN_SHRINK: usize = 8;

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
    use std::{collections::BTreeSet, sync::Arc};

    use datafusion::{
        arrow::{
            array::{Int64Array, StringArray},
            datatypes::{DataType, Field, Schema},
            record_batch::RecordBatch,
        },
        datasource::MemTable,
    };
    use datafusion_expr::{LogicalPlan, col, lit, logical_plan::table_scan};

    use super::super::DataDependentOptimizationRule;
    use super::{CompactionRule, apply_compaction_hints};

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

    /// How many compaction hints the rule collects for `sql` over a 64-row
    /// table `t(k, s)` with `k` = 0..63 and `s` = "x" on the first `x_rows`.
    async fn hint_count(sql: &str, x_rows: usize) -> usize {
        let ctx = tt_core::session::session_context();
        let schema = Arc::new(Schema::new(vec![
            Field::new("k", DataType::Int64, false),
            Field::new("s", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int64Array::from_iter_values(0..64)),
                Arc::new(StringArray::from_iter_values(
                    (0..64).map(|row| if row < x_rows { "x" } else { "y" }),
                )),
            ],
        )
        .unwrap();
        ctx.register_table(
            "t",
            Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap()),
        )
        .unwrap();
        let plan = ctx.sql(sql).await.unwrap().into_optimized_plan().unwrap();
        CompactionRule::new()
            .collect_hints(&ctx.state(), &plan)
            .unwrap()
            .len()
    }

    #[tokio::test]
    async fn a_filter_is_compacted_only_when_the_domain_shrinks_by_min_shrink() {
        assert_eq!(hint_count("SELECT k FROM t WHERE k < 8", 0).await, 1);
        assert_eq!(hint_count("SELECT k FROM t WHERE k < 9", 0).await, 0);
    }

    #[tokio::test]
    async fn a_like_filter_is_compacted_on_any_halving() {
        assert_eq!(hint_count("SELECT k FROM t WHERE s LIKE '%x%'", 9).await, 1);
    }
}

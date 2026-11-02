use datafusion::execution::context::SessionState;
use datafusion_common::{
    DataFusionError, Result as DataFusionResult,
    tree_node::{Transformed, TreeNode},
};
use datafusion_expr::{JoinType, LogicalPlan};
use std::collections::BTreeSet;
use tt_core::irs::nodes::plan::{
    proved_empty::{ProvedEmptyLogicalNode, proved_empty},
    result_check::ResultCheckLogicalNode,
};

use super::{
    DataDependentOptimizationRule, OptimizationHint, compaction::expressions_for_with_new_exprs,
    row_count,
};

/// Proves the lowest subtrees whose output is empty and prunes what only
/// passes their emptiness on ([`propagate_empty`]).
///
/// Below an empty node the rule descends to the input that makes it empty,
/// as long as [`propagate_empty`] carries that input's emptiness back up:
/// the lower the witness, the less of the plan is proved. A table scan is
/// never a witness: an empty table is the owner's to commit.
#[derive(Debug, Default)]
pub struct EmptySubtreeRule;

impl EmptySubtreeRule {
    pub fn new() -> Self {
        Self
    }
}

impl DataDependentOptimizationRule for EmptySubtreeRule {
    fn name(&self) -> &str {
        "proved_empty"
    }

    fn collect_hints(
        &self,
        session_state: &SessionState,
        plan: &LogicalPlan,
    ) -> DataFusionResult<Vec<OptimizationHint>> {
        let mut hints = Vec::new();
        collect(session_state, plan, &mut Vec::new(), &mut hints)?;
        #[cfg(feature = "test-utils")]
        if let Some(target_path) = tt_core::test_utils::dishonest_prover::forged_empty_path(plan) {
            hints.push(OptimizationHint::ProvedEmpty { target_path });
        }
        Ok(hints)
    }
}

fn collect(
    session_state: &SessionState,
    plan: &LogicalPlan,
    path: &mut Vec<usize>,
    hints: &mut Vec<OptimizationHint>,
) -> DataFusionResult<()> {
    if !is_result_check(plan)
        && !matches!(plan, LogicalPlan::TableScan(_))
        && row_count(session_state, plan)? == 0
    {
        let mut target_path = path.clone();
        lowest_empty(session_state, plan, &mut target_path)?;
        hints.push(OptimizationHint::ProvedEmpty { target_path });
        return Ok(());
    }
    for (index, input) in plan.inputs().into_iter().enumerate() {
        path.push(index);
        collect(session_state, input, path, hints)?;
        path.pop();
    }
    Ok(())
}

/// Extends `path` from the empty `plan` to the lowest empty node whose
/// emptiness [`propagate_empty`] carries up to `plan`.
fn lowest_empty(
    session_state: &SessionState,
    plan: &LogicalPlan,
    path: &mut Vec<usize>,
) -> DataFusionResult<()> {
    for index in empty_inputs_that_propagate(plan) {
        let input = plan.inputs()[index];
        if !matches!(input, LogicalPlan::TableScan(_)) && row_count(session_state, input)? == 0 {
            path.push(index);
            return lowest_empty(session_state, input, path);
        }
    }
    Ok(())
}

/// The inputs whose emptiness makes `plan` empty under [`propagate_empty`].
fn empty_inputs_that_propagate(plan: &LogicalPlan) -> Vec<usize> {
    match plan {
        LogicalPlan::Join(join) if join.join_type == JoinType::Inner => vec![0, 1],
        LogicalPlan::Aggregate(aggregate) if aggregate.group_expr.is_empty() => vec![],
        LogicalPlan::Filter(_)
        | LogicalPlan::Projection(_)
        | LogicalPlan::Sort(_)
        | LogicalPlan::Limit(_)
        | LogicalPlan::SubqueryAlias(_)
        | LogicalPlan::Distinct(_)
        | LogicalPlan::Aggregate(_) => vec![0],
        _ => vec![],
    }
}

/// Wraps each target in a `ProvedEmptyLogicalNode`, then propagates.
pub(super) fn apply_proved_empty_hints(
    plan: LogicalPlan,
    path: &mut Vec<usize>,
    remaining_paths: &mut BTreeSet<Vec<usize>>,
) -> DataFusionResult<LogicalPlan> {
    let wrapped = wrap_targets(plan, path, remaining_paths)?;
    propagate_empty(wrapped)
}

fn wrap_targets(
    plan: LogicalPlan,
    path: &mut Vec<usize>,
    remaining_paths: &mut BTreeSet<Vec<usize>>,
) -> DataFusionResult<LogicalPlan> {
    if remaining_paths.remove(path) {
        // The result check binds the claimed result, so it stays the root.
        if is_result_check(&plan) {
            return Err(DataFusionError::Plan(format!(
                "ProvedEmpty hint at path {path:?} targets the result check"
            )));
        }
        let schema = plan.schema().clone();
        return Ok(proved_empty(plan, schema));
    }
    let new_inputs = plan
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(index, input)| {
            path.push(index);
            let rewritten = wrap_targets(input.clone(), path, remaining_paths);
            path.pop();
            rewritten
        })
        .collect::<DataFusionResult<Vec<_>>>()?;
    plan.with_new_exprs(expressions_for_with_new_exprs(&plan), new_inputs)
}

/// Replaces each operator whose output is empty whenever one of its inputs
/// is by an empty table with the operator's schema, proved by that input's
/// witness: Filter, Projection, Sort, Limit, SubqueryAlias, Distinct, an
/// Aggregate with GROUP BY and an inner Join (whose other input is then not
/// proved at all). An Aggregate without GROUP BY outputs one row over no
/// rows, so it stays. Prover and verifier run this same rewrite.
pub fn propagate_empty(plan: LogicalPlan) -> DataFusionResult<LogicalPlan> {
    plan.transform_up(|plan| {
        let witness = empty_inputs_that_propagate(&plan)
            .into_iter()
            .find_map(|index| proved_empty_witness(plan.inputs()[index]).cloned());
        Ok(match witness {
            Some(witness) => {
                let schema = plan.schema().clone();
                Transformed::yes(proved_empty(witness, schema))
            }
            None => Transformed::no(plan),
        })
    })
    .map(|transformed| transformed.data)
}

fn proved_empty_witness(plan: &LogicalPlan) -> Option<&LogicalPlan> {
    let LogicalPlan::Extension(extension) = plan else {
        return None;
    };
    Some(
        extension
            .node
            .as_any()
            .downcast_ref::<ProvedEmptyLogicalNode>()?
            .witness(),
    )
}

pub(super) fn is_proved_empty(plan: &LogicalPlan) -> bool {
    proved_empty_witness(plan).is_some()
}

fn is_result_check(plan: &LogicalPlan) -> bool {
    matches!(
        plan,
        LogicalPlan::Extension(extension)
            if extension.node.as_any().is::<ResultCheckLogicalNode>()
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion_expr::{LogicalPlan, LogicalPlanBuilder, col, lit, logical_plan::table_scan};

    use super::{apply_proved_empty_hints, is_proved_empty, proved_empty_witness};

    fn scan(name: &str) -> LogicalPlanBuilder {
        let schema = Schema::new(vec![
            Field::new(format!("{name}_k"), DataType::Int64, false),
            Field::new(format!("{name}_v"), DataType::Int64, false),
        ]);
        table_scan(Some(name), &schema, None).unwrap()
    }

    fn apply(plan: LogicalPlan, target: Vec<usize>) -> datafusion_common::Result<LogicalPlan> {
        apply_proved_empty_hints(plan, &mut Vec::new(), &mut BTreeSet::from([target]))
    }

    /// `Join(Filter(a), b)` with the filter proved empty: the join becomes
    /// an empty table proved by the filter alone, with the join's schema.
    #[test]
    fn an_inner_join_with_an_empty_side_is_empty() {
        let right = scan("b").build().unwrap();
        let plan = scan("a")
            .filter(col("a_v").eq(lit(1)))
            .unwrap()
            .join(
                right,
                datafusion_expr::JoinType::Inner,
                (vec!["a_k"], vec!["b_k"]),
                None,
            )
            .unwrap()
            .project(vec![col("a_k"), col("b_v")])
            .unwrap()
            .build()
            .unwrap();
        let rewritten = apply(plan.clone(), vec![0, 0]).unwrap();
        assert!(is_proved_empty(&rewritten), "{rewritten}");
        assert_eq!(rewritten.schema(), plan.schema());
        let witness = proved_empty_witness(&rewritten).unwrap();
        assert!(matches!(witness, LogicalPlan::Filter(_)), "{witness}");
    }

    /// The filter under the join is the lowest empty node, and its
    /// emptiness reaches the root.
    #[tokio::test]
    async fn the_rule_proves_the_lowest_empty_node() {
        use std::sync::Arc;

        use datafusion::{arrow::record_batch::RecordBatch, datasource::MemTable};

        use super::super::{DataDependentOptimizationRule, OptimizationHint};
        use super::EmptySubtreeRule;

        let ctx = tt_core::session::session_context();
        for name in ["t", "u"] {
            let schema = Arc::new(Schema::new(vec![
                Field::new("k", DataType::Int64, false),
                Field::new("v", DataType::Int64, false),
            ]));
            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(datafusion::arrow::array::Int64Array::from(vec![1, 2, 3])),
                    Arc::new(datafusion::arrow::array::Int64Array::from(vec![4, 5, 6])),
                ],
            )
            .unwrap();
            ctx.register_table(
                name,
                Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap()),
            )
            .unwrap();
        }
        let plan = ctx
            .sql("SELECT t.k, u.v FROM t JOIN u ON t.k = u.k WHERE t.v > 100")
            .await
            .unwrap()
            .into_optimized_plan()
            .unwrap();
        let hints = EmptySubtreeRule::new()
            .collect_hints(&ctx.state(), &plan)
            .unwrap();
        let [OptimizationHint::ProvedEmpty { target_path }] = hints.as_slice() else {
            panic!("{hints:?}\n{plan}");
        };
        let rewritten = apply(plan.clone(), target_path.clone()).unwrap();
        assert!(is_proved_empty(&rewritten), "{rewritten}");
        let witness = proved_empty_witness(&rewritten).unwrap();
        assert!(matches!(witness, LogicalPlan::Filter(_)), "{witness}");
    }

    /// An aggregate without GROUP BY outputs a row over no rows.
    #[test]
    fn an_ungrouped_aggregate_stays() {
        let plan = scan("a")
            .filter(col("a_v").eq(lit(1)))
            .unwrap()
            .aggregate(
                Vec::<datafusion_expr::Expr>::new(),
                vec![datafusion::functions_aggregate::expr_fn::count(col("a_k"))],
            )
            .unwrap()
            .build()
            .unwrap();
        let rewritten = apply(plan, vec![0]).unwrap();
        let LogicalPlan::Aggregate(aggregate) = &rewritten else {
            panic!("{rewritten}");
        };
        assert!(is_proved_empty(&aggregate.input), "{rewritten}");
    }
}

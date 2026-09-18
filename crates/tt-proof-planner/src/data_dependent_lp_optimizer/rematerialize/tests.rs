//! Structural policy tests, not a claim that every order-sensitive query
//! previously admitted an invalid result. The current policy deliberately
//! rejects even some placements that a future order-demand analysis can allow.

use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    sync::Arc,
};

use datafusion::{
    arrow::{
        array::Int64Array,
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    },
    prelude::SessionContext,
};
use datafusion_common::{DFSchema, DFSchemaRef, DataFusionError, Result};
use datafusion_expr::{
    Expr, LogicalPlan, LogicalPlanBuilder, SortExpr, UserDefinedLogicalNodeCore, WindowFrame, col,
    expr::{AggregateFunction, WindowFunction},
    expr_fn::scalar_subquery,
    lit,
    logical_plan::{Extension, builder::table_scan},
};
use datafusion_functions_aggregate::sum::sum_udaf;
use tt_core::irs::nodes::plan::result_check::wrap_logical_plan as wrap_result;

use super::{RematerializeLogicalNode, RematerializeRule, contains_order_sensitive_operator};
use crate::data_dependent_lp_optimizer::{
    DataDependentOptimizationRule, OptimizationHint, OptimizationHints, apply_optimization_hints,
};

fn filter_plan() -> Result<LogicalPlan> {
    let schema = Schema::new(vec![Field::new("a", DataType::Int64, false)]);
    table_scan(Some("t"), &schema, None)?
        .filter(col("a").gt(lit(0_i64)))?
        .build()
}

fn hint(path: Vec<usize>) -> OptimizationHints {
    OptimizationHints {
        hints: vec![OptimizationHint::Rematerialize { target_path: path }],
    }
}

fn assert_rejected(plan: LogicalPlan, target_path: Vec<usize>) -> Result<()> {
    assert!(contains_order_sensitive_operator(&plan)?);
    // This guard runs before row-count execution. The schema-only scan used
    // here intentionally has no runtime provider for such execution.
    let state = SessionContext::new().state();
    assert!(
        RematerializeRule::new()
            .collect_hints(&state, &plan)?
            .is_empty()
    );
    assert!(matches!(
        apply_optimization_hints(plan, &hint(target_path)),
        Err(DataFusionError::Plan(message)) if message.contains("bag equality does not preserve order")
    ));
    Ok(())
}

#[test]
fn sort_plans_decline_collection_and_reject_replay() -> Result<()> {
    let plan = LogicalPlanBuilder::from(filter_plan()?)
        .sort(vec![col("a").sort(true, true)])?
        .build()?;
    // Even this otherwise-safe Filter below Sort is conservatively excluded.
    assert_rejected(plan, vec![0])
}

#[test]
fn limit_plans_decline_collection_and_reject_replay() -> Result<()> {
    let plan = LogicalPlanBuilder::from(filter_plan()?)
        .limit(0, Some(1))?
        .build()?;
    assert_rejected(plan, vec![0])
}

#[test]
fn table_scan_fetch_cannot_hide_a_pushed_down_limit() -> Result<()> {
    let schema = Schema::new(vec![Field::new("a", DataType::Int64, false)]);
    let mut scan_plan = table_scan(Some("t"), &schema, None)?.build()?;
    let LogicalPlan::TableScan(scan) = &mut scan_plan else {
        panic!("table_scan builder must produce a TableScan");
    };
    scan.fetch = Some(1);
    let plan = LogicalPlanBuilder::from(scan_plan)
        .filter(col("a").gt(lit(0_i64)))?
        .build()?;
    assert_rejected(plan, vec![])
}

#[test]
fn window_plans_decline_collection_and_reject_replay() -> Result<()> {
    let mut running_sum = WindowFunction::new(sum_udaf(), vec![col("a")]);
    running_sum.params.order_by = vec![col("a").sort(true, true)];
    running_sum.params.window_frame = WindowFrame::new(Some(true));
    let plan = LogicalPlanBuilder::from(filter_plan()?)
        .window(vec![Expr::WindowFunction(running_sum)])?
        .build()?;
    assert_rejected(plan, vec![0])
}

#[test]
fn distinct_on_plans_decline_collection_and_reject_replay() -> Result<()> {
    let plan = LogicalPlanBuilder::from(filter_plan()?)
        .distinct_on(
            vec![col("a")],
            vec![col("a")],
            Some(vec![SortExpr::new(col("a"), true, true)]),
        )?
        .build()?;
    assert_rejected(plan, vec![0])
}

#[test]
fn aggregate_local_order_by_is_detected_without_a_sort_node() -> Result<()> {
    let ordered_sum = Expr::AggregateFunction(AggregateFunction::new_udf(
        sum_udaf(),
        vec![col("a")],
        false,
        None,
        Some(vec![col("a").sort(true, true)]),
        None,
    ));
    let plan = LogicalPlanBuilder::from(filter_plan()?)
        .aggregate(Vec::<Expr>::new(), vec![ordered_sum])?
        .build()?;
    assert_rejected(plan, vec![0])
}

#[derive(Debug, Clone)]
struct UnknownExtension {
    schema: DFSchemaRef,
}

impl PartialEq for UnknownExtension {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for UnknownExtension {}

impl PartialOrd for UnknownExtension {
    fn partial_cmp(&self, _other: &Self) -> Option<Ordering> {
        Some(Ordering::Equal)
    }
}

impl Hash for UnknownExtension {
    fn hash<H: Hasher>(&self, state: &mut H) {
        "UnknownExtension".hash(state);
    }
}

impl UserDefinedLogicalNodeCore for UnknownExtension {
    fn name(&self) -> &str {
        "UnknownExtension"
    }

    fn inputs(&self) -> Vec<&LogicalPlan> {
        Vec::new()
    }

    fn schema(&self) -> &DFSchemaRef {
        &self.schema
    }

    fn expressions(&self) -> Vec<Expr> {
        Vec::new()
    }

    fn fmt_for_explain(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "UnknownExtension")
    }

    fn with_exprs_and_inputs(&self, exprs: Vec<Expr>, inputs: Vec<LogicalPlan>) -> Result<Self> {
        assert!(exprs.is_empty());
        assert!(inputs.is_empty());
        Ok(self.clone())
    }
}

#[test]
fn unknown_extension_nodes_fail_closed() -> Result<()> {
    let plan = LogicalPlan::Extension(Extension {
        node: Arc::new(UnknownExtension {
            schema: Arc::new(DFSchema::empty()),
        }),
    });
    assert_rejected(plan, vec![])
}

#[test]
fn unsupported_ordinary_distinct_fails_closed() -> Result<()> {
    let plan = LogicalPlanBuilder::from(filter_plan()?)
        .distinct()?
        .build()?;
    assert_rejected(plan, vec![0])
}

#[test]
fn projections_aliases_and_result_wrappers_do_not_hide_order_demand() -> Result<()> {
    let sorted = LogicalPlanBuilder::from(filter_plan()?)
        .sort(vec![col("a").sort(true, true)])?
        .build()?;
    let plan = LogicalPlanBuilder::from(sorted)
        .filter(col("a").lt(lit(10_i64)))?
        .alias("filtered")?
        .project(vec![col("a")])?
        .limit(0, Some(1))?
        .build()?;
    // ResultCheck -> Limit -> Projection -> Alias -> Filter -> Sort.
    assert_rejected(wrap_result(plan), vec![0, 0, 0, 0])
}

#[test]
fn expression_subqueries_do_not_hide_order_sensitive_nodes() -> Result<()> {
    let subquery = LogicalPlanBuilder::from(filter_plan()?)
        .limit(0, Some(1))?
        .build()?;
    let plan = LogicalPlanBuilder::from(filter_plan()?)
        .project(vec![
            col("a"),
            scalar_subquery(Arc::new(subquery)).alias("s"),
        ])?
        .build()?;
    assert_rejected(plan, vec![0])
}

#[test]
fn ordered_plan_without_hints_is_unchanged() -> Result<()> {
    let plan = LogicalPlanBuilder::from(filter_plan()?)
        .sort(vec![col("a").sort(true, true)])?
        .limit(0, Some(1))?
        .build()?;
    let rewritten = apply_optimization_hints(plan.clone(), &OptimizationHints::default())?;
    assert_eq!(rewritten, plan);
    Ok(())
}

#[test]
fn bag_only_collection_and_replay_still_work() -> Result<()> {
    let ctx = SessionContext::new();
    let schema = Arc::new(Schema::new(vec![Field::new("a", DataType::Int64, false)]));
    let batch = RecordBatch::try_new(
        schema,
        vec![Arc::new(Int64Array::from(vec![0, 1, 2, 3, 4, 5, 6, 7]))],
    )?;
    let plan = ctx
        .read_batch(batch)?
        .filter(col("a").lt(lit(2_i64)))?
        .select(vec![col("a")])?
        .into_unoptimized_plan();
    let plan = wrap_result(plan);
    assert!(!contains_order_sensitive_operator(&plan)?);
    let hints = OptimizationHints {
        hints: RematerializeRule::new().collect_hints(&ctx.state(), &plan)?,
    };
    assert_eq!(hints, hint(vec![0, 0]));
    let rewritten = apply_optimization_hints(plan, &hints)?;
    let projection = rewritten.inputs()[0];
    assert!(matches!(
        projection.inputs()[0],
        LogicalPlan::Extension(extension)
            if extension.node.as_any().is::<RematerializeLogicalNode>()
    ));
    Ok(())
}

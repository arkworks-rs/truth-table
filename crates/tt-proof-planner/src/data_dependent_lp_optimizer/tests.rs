//! Untrusted optimization hints must not remove unproved query obligations.

use std::sync::Arc;

use datafusion::{
    arrow::{
        array::Int32Array,
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    },
    datasource::{MemTable, provider_as_source},
    prelude::SessionContext,
};
use datafusion_common::DataFusionError;
use datafusion_expr::{LogicalPlan, LogicalPlanBuilder, col, lit};
use tt_core::irs::nodes::plan::rematerialize::RematerializeLogicalNode;

use super::{
    DataDependentOptimizationRule, OptimizationHint, OptimizationHints, TruncateEmptyPayloadRule,
    apply_optimization_hints,
};

fn scan(values: Vec<i32>) -> LogicalPlan {
    let schema = Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::Int32,
        false,
    )]));
    let batch =
        RecordBatch::try_new(schema.clone(), vec![Arc::new(Int32Array::from(values))]).unwrap();
    let table = MemTable::try_new(schema, vec![vec![batch]]).unwrap();
    LogicalPlanBuilder::scan("items", provider_as_source(Arc::new(table)), None)
        .unwrap()
        .build()
        .unwrap()
}

fn nonempty_scan() -> LogicalPlan {
    scan(vec![7])
}

fn empty_scan() -> LogicalPlan {
    scan(Vec::new())
}

fn assert_truncation_rejected(plan: LogicalPlan, hints: Vec<OptimizationHint>) {
    let error = apply_optimization_hints(plan, &OptimizationHints { hints })
        .expect_err("unproved truncation must not be replayed");
    assert!(matches!(error, DataFusionError::Plan(message) if message.contains("emptiness proof")));
}

#[test]
fn truncate_hint_cannot_erase_a_nonempty_scan() {
    assert_truncation_rejected(
        nonempty_scan(),
        vec![OptimizationHint::Truncate {
            target_path: vec![],
        }],
    );
}

#[test]
fn truncate_hint_cannot_erase_a_nested_nonempty_scan() {
    let plan = LogicalPlanBuilder::from(nonempty_scan())
        .project(vec![col("value")])
        .unwrap()
        .build()
        .unwrap();
    assert_truncation_rejected(
        plan,
        vec![OptimizationHint::Truncate {
            target_path: vec![0],
        }],
    );
}

#[test]
fn mixed_hints_cannot_bypass_truncation_rejection() {
    for hints in [
        vec![
            OptimizationHint::Rematerialize {
                target_path: vec![],
            },
            OptimizationHint::Truncate {
                target_path: vec![],
            },
        ],
        vec![
            OptimizationHint::Truncate {
                target_path: vec![],
            },
            OptimizationHint::Rematerialize {
                target_path: vec![],
            },
        ],
    ] {
        assert_truncation_rejected(nonempty_scan(), hints);
    }
}

#[test]
fn truncation_rejected_even_for_an_invalid_target_path() {
    assert_truncation_rejected(
        nonempty_scan(),
        vec![OptimizationHint::Truncate {
            target_path: vec![usize::MAX],
        }],
    );
}

#[test]
fn truncate_hint_is_rejected_even_for_a_structurally_empty_plan() {
    assert_truncation_rejected(
        LogicalPlanBuilder::empty(false).build().unwrap(),
        vec![OptimizationHint::Truncate {
            target_path: vec![],
        }],
    );
}

#[test]
fn no_hints_preserve_the_nonempty_plan() {
    let plan = nonempty_scan();
    let replayed = apply_optimization_hints(plan.clone(), &OptimizationHints::default()).unwrap();
    assert_eq!(replayed, plan);
}

#[test]
fn no_hints_preserve_a_structurally_empty_plan() {
    let plan = LogicalPlanBuilder::empty(false).build().unwrap();
    let replayed = apply_optimization_hints(plan.clone(), &OptimizationHints::default()).unwrap();
    assert_eq!(replayed, plan);
}

#[test]
fn supported_rematerialize_hint_still_replays() {
    let plan = LogicalPlanBuilder::from(nonempty_scan())
        .filter(col("value").gt(lit(0_i32)))
        .unwrap()
        .build()
        .unwrap();
    let replayed = apply_optimization_hints(
        plan,
        &OptimizationHints {
            hints: vec![OptimizationHint::Rematerialize {
                target_path: vec![],
            }],
        },
    )
    .unwrap();
    assert!(matches!(
        replayed,
        LogicalPlan::Extension(extension)
            if extension.node.as_any().is::<RematerializeLogicalNode>()
    ));
}

#[test]
fn explicitly_enabled_legacy_collector_fails_closed() {
    let context = SessionContext::new();
    let error = TruncateEmptyPayloadRule::new()
        .collect_hints(&context.state(), &nonempty_scan())
        .expect_err("an explicit rule list must not re-enable unproved truncation");
    assert!(matches!(error, DataFusionError::Plan(message) if message.contains("emptiness proof")));
}

#[test]
fn explicitly_enabled_legacy_collector_does_not_trust_observed_emptiness() {
    let context = SessionContext::new();
    let error = TruncateEmptyPayloadRule::new()
        .collect_hints(&context.state(), &empty_scan())
        .expect_err("observed emptiness is not a verifier-checked certificate");
    assert!(matches!(error, DataFusionError::Plan(message) if message.contains("emptiness proof")));
}

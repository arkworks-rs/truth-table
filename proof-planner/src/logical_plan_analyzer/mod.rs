use std::sync::Arc;

use datafusion::{
    config::ConfigOptions,
    logical_expr::LogicalPlan,
    optimizer::{
        analyzer::{
            function_rewrite::ApplyFunctionRewrites,
            resolve_grouping_function::ResolveGroupingFunction, AnalyzerRule,
        },
        Analyzer,
    },
};

mod type_coercion;
use self::type_coercion::CustomizedTypeCoercion;

pub(crate) fn logical_plan_analyzer_rules() -> Vec<Arc<dyn AnalyzerRule + Send + Sync>> {
    vec![
        Arc::new(ApplyFunctionRewrites::default()),
        Arc::new(ResolveGroupingFunction::new()),
        Arc::new(CustomizedTypeCoercion::new()),
    ]
}

pub(crate) fn analyze_logical_plan(
    plan: LogicalPlan,
    analyzer_rules: Vec<Arc<dyn AnalyzerRule + Send + Sync>>,
) -> LogicalPlan {
    let cfg = ConfigOptions::new();

    Analyzer::with_rules(analyzer_rules)
        .execute_and_check(plan, &cfg, |_plan_after_rule, _rule| {})
        .unwrap()
}

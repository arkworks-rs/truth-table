mod add_avg_support;
mod align_agg_input_to_output;
mod align_binary_operands;
mod common;

use std::sync::Arc;

use add_avg_support::AddAvgSupport;
use align_agg_input_to_output::AlignAggInputToOutput;
use align_binary_operands::AlignBinaryOperands;

use datafusion::{
    config::ConfigOptions,
    logical_expr::LogicalPlan,
    optimizer::{
        analyzer::{
            expand_wildcard_rule::ExpandWildcardRule, function_rewrite::ApplyFunctionRewrites,
            inline_table_scan::InlineTableScan, resolve_grouping_function::ResolveGroupingFunction,
            type_coercion::TypeCoercion, AnalyzerRule,
        },
        Analyzer,
    },
};

pub fn rules() -> Vec<Arc<dyn AnalyzerRule + Send + Sync>> {
    vec![
        Arc::new(ApplyFunctionRewrites::default()),
        Arc::new(InlineTableScan::new()),
        Arc::new(ExpandWildcardRule::new()),
        Arc::new(ResolveGroupingFunction::new()),
        Arc::new(TypeCoercion::new()),
        Arc::new(AlignBinaryOperands::new()),
        Arc::new(AddAvgSupport::new()),
        Arc::new(AlignAggInputToOutput::new()),
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

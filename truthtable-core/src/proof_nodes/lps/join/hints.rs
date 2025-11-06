use datafusion_expr::LogicalPlan;
use indexmap::IndexMap;

use crate::proof_nodes::{HintGenerationPlan, OUTPUT_PLAN_KEY};

pub(crate) fn build_join_hint_generation_plans(
    plan: LogicalPlan,
) -> IndexMap<String, HintGenerationPlan> {
    let mut plans = IndexMap::new();
    plans.insert(
        OUTPUT_PLAN_KEY.to_string(),
        HintGenerationPlan::new_materialized(OUTPUT_PLAN_KEY.to_string(), plan.clone()),
    );

    plans
}

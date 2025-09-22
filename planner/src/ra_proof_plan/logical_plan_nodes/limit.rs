use crate::ra_proof_plan::{primary_witness_plan, relative_plan_opt, ProofPlan, ProofPlanNodeType};
use datafusion::{
    logical_expr::{self as df, LogicalPlan, LogicalPlanBuilder},
    prelude::SessionContext,
};
use std::{collections::HashMap, sync::Arc};

pub struct LimitNode {
    pub skip: Option<Arc<dyn ProofPlan>>,
    pub fetch: Option<Arc<dyn ProofPlan>>,
    pub input: Arc<dyn ProofPlan>,
    pub node_type: ProofPlanNodeType,
    pub witness_generation_plans: HashMap<String, df::LogicalPlan>,
}

impl LimitNode {
    /// Build a relative plan by applying a logical Limit (skip/fetch).
    /// Note: This uses DataFusion's Limit operator which reduces row count.
    /// Columns are preserved as-is.
    pub fn make_relative_plan(
        input_plan: LogicalPlan,
        _skip: Option<Arc<dyn ProofPlan>>,
        _fetch: Option<Arc<dyn ProofPlan>>,
    ) -> LogicalPlan {
        todo!()
    }

    pub fn new(
        ctx: &SessionContext,
        skip: Option<Arc<dyn ProofPlan>>,
        fetch: Option<Arc<dyn ProofPlan>>,
        input_plan: LogicalPlan,
        input: Arc<dyn ProofPlan>,
    ) -> Self {
        let child_plan = primary_witness_plan(&input)
            .or_else(|| relative_plan_opt(&input))
            .expect("limit child witness plan unavailable");
        let relative_plan =
            Self::make_relative_plan(child_plan.clone(), skip.clone(), fetch.clone());
        let mut witness_generation_plans = HashMap::new();
        witness_generation_plans.insert("absolute_output".to_string(), relative_plan.clone());
        witness_generation_plans.insert("relative_output".to_string(), relative_plan.clone());
        Self {
            skip,
            fetch,
            input,
            node_type: ProofPlanNodeType::LogicalPlan(relative_plan.clone()),
            witness_generation_plans,
        }
    }
}

impl ProofPlan for LimitNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        vec![&self.input]
    }

    fn node_type(&self) -> ProofPlanNodeType {
        self.node_type.clone()
    }

    fn witness_generation_plans(&self) -> HashMap<String, df::LogicalPlan> {
        self.witness_generation_plans.clone()
    }
}

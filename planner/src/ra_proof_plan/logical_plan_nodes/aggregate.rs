use std::{collections::HashMap, sync::Arc};

use crate::ra_proof_plan::{ProofPlan, ProofPlanNodeType};
use datafusion::{logical_expr::LogicalPlan, prelude::SessionContext};

pub struct AggregateNode {
    pub group_expr: Vec<Arc<dyn ProofPlan>>,
    pub aggr_expr: Vec<Arc<dyn ProofPlan>>,
    pub input: Arc<dyn ProofPlan>,
    pub node_type: ProofPlanNodeType,
    pub witness_generation_plans: HashMap<String, LogicalPlan>,
}

impl AggregateNode {
    pub fn make_relative_plan(
        group_expr: Vec<Arc<dyn ProofPlan>>,
        aggr_expr: Vec<Arc<dyn ProofPlan>>,
        input_plan: LogicalPlan,
    ) -> LogicalPlan {
        todo!()
    }

    pub fn new(
        ctx: &mut SessionContext,
        group_expr: Vec<Arc<dyn ProofPlan>>,
        aggr_expr: Vec<Arc<dyn ProofPlan>>,
        input_plan: LogicalPlan,
        input: Arc<dyn ProofPlan>,
    ) -> Self {
        let relative_plan =
            Self::make_relative_plan(group_expr.clone(), aggr_expr.clone(), input_plan.clone());
        let absolute_plan = ctx.state().optimize(&relative_plan).unwrap();
        let mut witness_generation_plans = HashMap::new();
        witness_generation_plans.insert("absolute_output".to_string(), absolute_plan);
        witness_generation_plans.insert("relative_output".to_string(), relative_plan.clone());
        AggregateNode {
            group_expr,
            aggr_expr,
            input,
            node_type: ProofPlanNodeType::LogicalPlan(relative_plan),
            witness_generation_plans,
        }
    }
}

impl ProofPlan for AggregateNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        vec![&self.input]
    }

    fn node_type(&self) -> ProofPlanNodeType {
        self.node_type.clone()
    }

    fn witness_generation_plans(&self) -> HashMap<String, LogicalPlan> {
        self.witness_generation_plans.clone()
    }
}

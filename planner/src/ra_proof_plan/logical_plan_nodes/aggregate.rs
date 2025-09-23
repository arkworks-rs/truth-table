use std::{collections::HashMap, sync::Arc};

use crate::ra_proof_plan::{output_logical_plan, ProofPlan, ProofPlanNodeType};
use datafusion::{logical_expr::LogicalPlan, prelude::SessionContext};

pub struct AggregateNode {
    pub group_expr: Vec<Arc<dyn ProofPlan>>,
    pub aggr_expr: Vec<Arc<dyn ProofPlan>>,
    pub input: Arc<dyn ProofPlan>,
    pub node_type: ProofPlanNodeType,
    pub witness_generation_plans: HashMap<String, LogicalPlan>,
}

impl AggregateNode {
    pub fn build_output_plan(
        group_expr: Vec<Arc<dyn ProofPlan>>,
        aggr_expr: Vec<Arc<dyn ProofPlan>>,
        input_plan: LogicalPlan,
    ) -> LogicalPlan {
        todo!()
    }
}

impl ProofPlan for AggregateNode {
    fn from_logical_plan(ctx: &SessionContext, plan: LogicalPlan) -> Self
    where
        Self: Sized,
    {
        todo!()
    }
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

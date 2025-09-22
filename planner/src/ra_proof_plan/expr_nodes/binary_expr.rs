use std::{collections::HashMap, sync::Arc};

use datafusion::logical_expr::{BinaryExpr, Expr, LogicalPlan, LogicalPlanBuilder, Operator};

use crate::ra_proof_plan::{expr_to_proof_plan, ProofPlan, ProofPlanNodeType};

#[derive(Clone)]
pub struct BinaryExprNode {
    pub node_type: ProofPlanNodeType,
    pub left_proof_plan: Arc<dyn ProofPlan>,
    pub right_proof_plan: Arc<dyn ProofPlan>,
    pub witness_generation_plans: HashMap<String, LogicalPlan>,
}

impl BinaryExprNode {
    pub fn new(bin_expr: BinaryExpr, input_plan: LogicalPlan) -> Self {
        let left_expr = bin_expr.left.as_ref().clone();
        let right_expr = bin_expr.right.as_ref().clone();
        let witness_generation_plans =
            Self::build_witness_plans(bin_expr.clone(), input_plan.clone());

        Self {
            node_type: ProofPlanNodeType::Expr(Expr::BinaryExpr(bin_expr)),
            left_proof_plan: expr_to_proof_plan(left_expr, &input_plan),
            right_proof_plan: expr_to_proof_plan(right_expr, &input_plan),
            witness_generation_plans,
        }
    }

    fn build_witness_plans(
        bin_expr: BinaryExpr,
        input_plan: LogicalPlan,
    ) -> HashMap<String, LogicalPlan> {
        match bin_expr.op {
            Operator::Eq
            | Operator::Lt
            | Operator::Gt
            | Operator::GtEq
            | Operator::LtEq
            | Operator::NotEq => {
                let eq_expr = Expr::BinaryExpr(bin_expr).alias("expr_output");
                let plan = LogicalPlanBuilder::from(input_plan)
                    .project(vec![eq_expr])
                    .unwrap()
                    .build()
                    .unwrap();
                HashMap::from([(String::from("output"), plan)])
            },
            _ => HashMap::new(),
        }
    }
}

impl ProofPlan for BinaryExprNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn node_type(&self) -> ProofPlanNodeType {
        self.node_type.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        vec![&self.left_proof_plan, &self.right_proof_plan]
    }
    fn witness_generation_plans(&self) -> HashMap<String, LogicalPlan> {
        self.witness_generation_plans.clone()
    }
}

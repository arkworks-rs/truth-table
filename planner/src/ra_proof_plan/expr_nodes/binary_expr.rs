use std::{collections::HashMap, sync::Arc};

use datafusion::{
    logical_expr::{BinaryExpr, Expr, LogicalPlan, LogicalPlanBuilder, Operator},
    prelude::case,
};

use crate::ra_proof_plan::{expr_to_proof_plan, ProofPlan, ProofPlanNodeType};
#[derive(Clone)]
pub struct BinaryExprNode {
    pub node_type: ProofPlanNodeType,
    pub left_proof_plan: Arc<dyn ProofPlan>,
    pub right_proof_plan: Arc<dyn ProofPlan>,
    pub witness_generation_plans: HashMap<String, LogicalPlan>,
}

impl BinaryExprNode {
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
                let bool_expr = Expr::BinaryExpr(bin_expr).alias("expr_output");
                let bool_plan = LogicalPlanBuilder::from(input_plan.clone())
                    .project(vec![bool_expr])
                    .unwrap()
                    .build()
                    .unwrap();
                let one = Expr::Literal(datafusion::scalar::ScalarValue::Int64(Some(1)));
                let zero = Expr::Literal(datafusion::scalar::ScalarValue::Int64(Some(0)));

                let selector = case(datafusion::prelude::col("expr_output"))
                    .when(
                        Expr::Literal(datafusion::scalar::ScalarValue::Boolean(Some(true))),
                        one.clone(),
                    )
                    .otherwise(zero.clone())
                    .unwrap()
                    .alias("expr_output");

                let plan = LogicalPlanBuilder::from(bool_plan)
                    .project(vec![selector])
                    .unwrap()
                    .build()
                    .unwrap();

                HashMap::from([(String::from("expr_output"), input_plan)])
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

    fn from_expr(
        ctx: &datafusion::prelude::SessionContext,
        expr: Expr,
        parent_logical_plan: datafusion::logical_expr::LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        let bin_expr = match expr.clone() {
            Expr::BinaryExpr(b) => b,
            _ => panic!("expected binary expression"),
        };
        let left_expr = bin_expr.left.as_ref().clone();
        let right_expr = bin_expr.right.as_ref().clone();
        let witness_generation_plans =
            Self::build_witness_plans(bin_expr.clone(), parent_logical_plan.clone());

        Self {
            node_type: ProofPlanNodeType::Expr(expr),
            left_proof_plan: expr_to_proof_plan(ctx, left_expr, &parent_logical_plan),
            right_proof_plan: expr_to_proof_plan(ctx, right_expr, &parent_logical_plan),
            witness_generation_plans,
        }
    }
}

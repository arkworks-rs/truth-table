use std::{collections::HashMap, sync::Arc};

use crate::nodes::{ProverNode, ProverNodeNodeId, expr_to_proof_plan};
use datafusion::{
    logical_expr::{BinaryExpr, Expr, LogicalPlan, LogicalPlanBuilder, Operator},
    prelude::case,
};
#[derive(Clone)]
pub struct BinaryExprNode {
    pub node_id: ProverNodeNodeId,
    pub left_proof_plan: Arc<dyn ProverNode>,
    pub right_proof_plan: Arc<dyn ProverNode>,
    pub proof_trees: HashMap<String, LogicalPlan>,
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

impl ProverNode for BinaryExprNode {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn node_id(&self) -> ProverNodeNodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode>> {
        vec![&self.left_proof_plan, &self.right_proof_plan]
    }
    fn proof_trees(&self) -> HashMap<String, LogicalPlan> {
        self.proof_trees.clone()
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
        let proof_trees =
            Self::build_witness_plans(bin_expr.clone(), parent_logical_plan.clone());

        Self {
            node_id: ProverNodeNodeId::Expr(expr),
            left_proof_plan: expr_to_proof_plan(ctx, left_expr, &parent_logical_plan),
            right_proof_plan: expr_to_proof_plan(ctx, right_expr, &parent_logical_plan),
            proof_trees,
        }
    }

    fn piop_plan(&self) {
        todo!()
    }
}

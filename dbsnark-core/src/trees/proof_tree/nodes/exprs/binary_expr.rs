use std::{collections::HashMap, sync::Arc};

use crate::trees::proof_tree::{
    ProofTree,
    nodes::{ProverNode, ProverNodeNodeId},
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{
    logical_expr::{BinaryExpr, Expr, LogicalPlan, LogicalPlanBuilder, Operator},
    prelude::case,
};
#[derive(Clone)]
pub struct BinaryExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub node_id: ProverNodeNodeId,
    pub left_proof_plan: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub right_proof_plan: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub hint_generation_plans: HashMap<String, LogicalPlan>,
}

impl<F, MvPCS, UvPCS> BinaryExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
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

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for BinaryExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn node_id(&self) -> ProverNodeNodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        vec![&self.left_proof_plan, &self.right_proof_plan]
    }
    fn hint_generation_plans(&self) -> HashMap<String, LogicalPlan> {
        self.hint_generation_plans.clone()
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
        let hint_generation_plans =
            Self::build_witness_plans(bin_expr.clone(), parent_logical_plan.clone());

        Self {
            node_id: ProverNodeNodeId::Expr(expr),
            left_proof_plan: ProofTree::<F, MvPCS, UvPCS>::from_expr(
                ctx,
                left_expr,
                &parent_logical_plan,
            ),
            right_proof_plan: ProofTree::<F, MvPCS, UvPCS>::from_expr(
                ctx,
                right_expr,
                &parent_logical_plan,
            ),
            hint_generation_plans,
        }
    }

        fn append_virtual_witness(
        &self,
        piop_tree: &mut crate::trees::piop_tree::PIOPTree<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }
}

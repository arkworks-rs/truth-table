use crate::{
    id::NodeId,
    verifier_trees::proof_tree::{VerifierProofTree, nodes::VerifierNode},
};
use std::{collections::HashMap, sync::Arc};

use crate::{verifier_trees, verifier_trees::piop_tree::VerifierPIOPTree};
use arithmetic::{col::TrackedCol, table::TrackedTable};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::Prover,
};
use datafusion::{
    arrow::datatypes::{Field, FieldRef},
    logical_expr::{BinaryExpr, Expr, LogicalPlan, LogicalPlanBuilder, Operator},
    prelude::case,
};
use ra_toolbox::expr_piop::binary_expr::{BinaryExprPIOP, BinaryExprPIOPProverInput};
#[derive(Clone)]
pub struct BinaryExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub node_id: NodeId,
    pub left_proof_plan: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub right_proof_plan: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub hint_generation_plans: HashMap<String, LogicalPlan>,
}

impl<F, MvPCS, UvPCS> BinaryExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn requires_materialized_witness(op: Operator) -> bool {
        matches!(
            op,
            Operator::Eq
                | Operator::Lt
                | Operator::Gt
                | Operator::GtEq
                | Operator::LtEq
                | Operator::NotEq
                | Operator::Or
        )
    }
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
        if Self::requires_materialized_witness(bin_expr.op) {
            let bool_expr = Expr::BinaryExpr(bin_expr).alias("output_plan");
            let bool_plan = LogicalPlanBuilder::from(input_plan.clone())
                .project(vec![bool_expr])
                .unwrap()
                .build()
                .unwrap();
            let one = Expr::Literal(datafusion::scalar::ScalarValue::Int64(Some(1)));
            let zero = Expr::Literal(datafusion::scalar::ScalarValue::Int64(Some(0)));

            let selector = case(datafusion::prelude::col("output_plan"))
                .when(
                    Expr::Literal(datafusion::scalar::ScalarValue::Boolean(Some(true))),
                    one.clone(),
                )
                .otherwise(zero.clone())
                .unwrap()
                .alias("output_plan");

            let plan = LogicalPlanBuilder::from(bool_plan)
                .project(vec![selector])
                .unwrap()
                .build()
                .unwrap();

            HashMap::from([(String::from("output_plan"), plan)])
        } else {
            HashMap::new()
        }
    }
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for BinaryExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        vec![&self.left_proof_plan, &self.right_proof_plan]
    }
    fn hint_generation_plans(&self) -> HashMap<String, LogicalPlan> {
        self.hint_generation_plans.clone()
    }

    fn from_expr(
        ctx: &datafusion::prelude::SessionContext,
        prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
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
            node_id: NodeId::Expr(expr),
            left_proof_plan: VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
                ctx,
                prover_ctx.clone(),
                left_expr,
                &parent_logical_plan,
            ),
            right_proof_plan: VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
                ctx,
                prover_ctx,
                right_expr,
                &parent_logical_plan,
            ),
            hint_generation_plans,
        }
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut crate::verifier_trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
        // if let Expr::BinaryExpr(bin_expr) = self.node_id.to_expr().unwrap() {
        //     if !Self::requires_materialized_witness(bin_expr.op) {
        //         let size = piop_tree
        //             .table(&self.left_proof_plan.node_id(), "output_plan")
        //             .unwrap()
        //             .size();
        //         let left_col = piop_tree
        //             .table(&self.left_proof_plan.node_id(), "output_plan")
        //             .unwrap()
        //             .col(0)
        //             .clone();
        //         let right_col = piop_tree
        //             .table(&self.right_proof_plan.node_id(), "output_plan")
        //             .unwrap()
        //             .col(0)
        //             .clone();
        //         let output_data_poly = match bin_expr.op {
        //             Operator::And => {
        //                 let data_mult = left_col.data_poly() *
        // right_col.data_poly();

        //                 match (left_col.actvtr_poly(),
        // right_col.actvtr_poly()) {                     (Some(l),
        // Some(r)) => &(l * r) * &data_mult,
        // (Some(l), None) => l * &data_mult,                     (None,
        // Some(r)) => r * &data_mult,                     (None, None)
        // => data_mult,                 }
        //             },
        //             _ => panic!("unsupported operator for virtual witness"),
        //         };
        //         let field_ref = FieldRef::new(Field::new(
        //             "output",
        //             datafusion::arrow::datatypes::DataType::BinaryView,
        //             false,
        //         ));

        //         let output_table =
        //             TrackedTable::new(None, vec![(field_ref,
        // output_data_poly)], size);         piop_tree.add_table(
        //             self.node_id.clone(),
        //             "output_plan".to_string(),
        //             output_table,
        //         );
        //     }
        // }
    }
    fn verify_piop(
        &self,
        prover: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        todo!()
        // let op = match self.node_id.to_expr().unwrap() {
        //     Expr::BinaryExpr(b) => b.op,
        //     _ => panic!("expected binary expression"),
        // };
        // let left_col = piop_tree
        //     .table(&self.left_proof_plan.node_id(), "output_plan")
        //     .unwrap()
        //     .col(0)
        //     .clone();
        // let right_col = piop_tree
        //     .table(&self.right_proof_plan.node_id(), "output_plan")
        //     .unwrap()
        //     .col(0)
        //     .clone();

        // let output_col = piop_tree
        //     .table(&self.node_id, "output_plan")
        //     .unwrap()
        //     .col(0)
        //     .clone();
        // let binary_expr_piop_verifier_input: BinaryExprPIOPProverInput<F,
        // MvPCS, UvPCS> =     BinaryExprPIOPProverInput {
        //         op,
        //         left_col,
        //         right_col,
        //         output_col,
        //     };
        // BinaryExprPIOP::<F, MvPCS, UvPCS>::prove(prover,
        // binary_expr_piop_verifier_input)
    }
}

// Combined dbsnark-core/src/prover/nodes/exprs/binary_expr.rs and
// dbsnark-core/src/verifier/nodes/exprs/binary_expr.rs

use crate::proof_nodes::id::NodeId;
use crate::proof_nodes::OUTPUT_PLAN_KEY;
use crate::{

    proof_nodes::{cost::ProvingCost, prover::ProverNode, verifier::VerifierNode},
    prover::trees::{piop_tree::ProverPIOPTree, proof_tree::ProverProofTree},
    verifier::trees::{piop_tree::VerifierPIOPTree, proof_tree::VerifierProofTree},
};

use arithmetic::{
    col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle, ACTIVATOR_COL_NAME,
};
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
    prelude::{case, col},
};
use indexmap::IndexMap;
use ra_toolbox::expr_piop::binary_expr::{
    BinaryExprPIOP, BinaryExprPIOPProverInput, BinaryExprPIOPVerifierInput,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct ProverBinaryExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub node_id: NodeId,
    pub left_proof_plan: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub right_proof_plan: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub hint_generation_plans: IndexMap<String, LogicalPlan>,
}

impl<F, MvPCS, UvPCS> ProverBinaryExprNode<F, MvPCS, UvPCS>
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

impl<F, MvPCS, UvPCS> ProverBinaryExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn build_witness_plans(
        bin_expr: BinaryExpr,
        input_plan: LogicalPlan,
    ) -> IndexMap<String, LogicalPlan> {
        if Self::requires_materialized_witness(bin_expr.op) {
            let bool_expr = Expr::BinaryExpr(bin_expr).alias(OUTPUT_PLAN_KEY);
            let bool_plan = LogicalPlanBuilder::from(input_plan.clone())
                .project(vec![bool_expr.clone(), col(ACTIVATOR_COL_NAME)])
                .unwrap()
                .build()
                .unwrap();
            let one = Expr::Literal(datafusion::scalar::ScalarValue::Int64(Some(1)));
            let zero = Expr::Literal(datafusion::scalar::ScalarValue::Int64(Some(0)));

            let selector = case(datafusion::prelude::col(OUTPUT_PLAN_KEY))
                .when(
                    Expr::Literal(datafusion::scalar::ScalarValue::Boolean(Some(true))),
                    one.clone(),
                )
                .otherwise(zero.clone())
                .unwrap()
                .alias(OUTPUT_PLAN_KEY);

            let plan = LogicalPlanBuilder::from(bool_plan)
                .project(vec![selector, col(ACTIVATOR_COL_NAME)])
                .unwrap()
                .build()
                .unwrap();

            IndexMap::from([(String::from(OUTPUT_PLAN_KEY), plan)])
        } else {
            IndexMap::new()
        }
    }
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for ProverBinaryExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        vec![&self.left_proof_plan, &self.right_proof_plan]
    }
    fn hint_generation_plans(&self) -> IndexMap<String, LogicalPlan> {
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
            left_proof_plan: ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                ctx,
                prover_ctx.clone(),
                left_expr,
                &parent_logical_plan,
            ),
            right_proof_plan: ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                ctx,
                prover_ctx,
                right_expr,
                &parent_logical_plan,
            ),
            hint_generation_plans,
        }
    }

    fn cost(
        &self,
        _statistics: datafusion::common::Statistics,
        _schema: datafusion::arrow::datatypes::SchemaRef,
    ) -> ProvingCost {
        todo!()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
        if let Expr::BinaryExpr(bin_expr) = self.node_id.to_expr().unwrap() {
            if !Self::requires_materialized_witness(bin_expr.op) {
                let log_size = piop_tree
                    .tracked_table(&self.left_proof_plan.node_id(), OUTPUT_PLAN_KEY)
                    .unwrap()
                    .log_size();
                let left_col = piop_tree
                    .tracked_table(&self.left_proof_plan.node_id(), OUTPUT_PLAN_KEY)
                    .unwrap()
                    .tracked_col_by_ind(0)
                    .clone();
                let right_col = piop_tree
                    .tracked_table(&self.right_proof_plan.node_id(), OUTPUT_PLAN_KEY)
                    .unwrap()
                    .tracked_col_by_ind(0)
                    .clone();
                let output_data_tracked_poly = match bin_expr.op {
                    Operator::And => {
                        let data_mult =
                            &left_col.data_tracked_poly() * &right_col.data_tracked_poly();

                        match (
                            left_col.activator_tracked_poly(),
                            right_col.activator_tracked_poly(),
                        ) {
                            (Some(l), Some(r)) => &(&l * &r) * &data_mult,
                            (Some(l), None) => &l * &data_mult,
                            (None, Some(r)) => &r * &data_mult,
                            (None, None) => data_mult,
                        }
                    },
                    _ => panic!("unsupported operator for virtual witness"),
                };
                let field_ref = FieldRef::new(Field::new(
                    "output",
                    datafusion::arrow::datatypes::DataType::BinaryView,
                    false,
                ));
                let output_activator = match (
                    left_col.activator_tracked_poly(),
                    right_col.activator_tracked_poly(),
                ) {
                    (Some(l), Some(r)) => {
                        debug_assert_eq!(l, r, "AND expects matching activators");
                        Some(l)
                    },
                    (Some(l), None) => Some(l),
                    (None, Some(r)) => Some(r),
                    (None, None) => None,
                };
                let mut columns = IndexMap::from([(field_ref, output_data_tracked_poly)]);
                if let Some(activator_poly) = output_activator {
                    let activator_field = FieldRef::new(Field::new(
                        arithmetic::ACTIVATOR_COL_NAME,
                        datafusion::arrow::datatypes::DataType::Boolean,
                        true,
                    ));
                    columns.insert(activator_field, activator_poly);
                }
                let output_table = TrackedTable::new(None, columns, log_size);
                piop_tree.add_table(
                    self.node_id.clone(),
                    OUTPUT_PLAN_KEY.to_string(),
                    output_table,
                );
            }
        }
    }
    fn prove_piop(
        &self,
        prover: &mut Prover<F, MvPCS, UvPCS>,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let op = match self.node_id.to_expr().unwrap() {
            Expr::BinaryExpr(b) => b.op,
            _ => panic!("expected binary expression"),
        };
        let left_col = piop_tree
            .tracked_table(&self.left_proof_plan.node_id(), OUTPUT_PLAN_KEY)
            .unwrap()
            .tracked_col_by_ind(0)
            .clone();
        let right_col = piop_tree
            .tracked_table(&self.right_proof_plan.node_id(), OUTPUT_PLAN_KEY)
            .unwrap()
            .tracked_col_by_ind(0)
            .clone();

        let raw_output_col = piop_tree
            .tracked_table(&self.node_id, OUTPUT_PLAN_KEY)
            .unwrap()
            .tracked_col_by_ind(0)
            .clone();
        let output_activator = match (
            left_col.activator_tracked_poly(),
            raw_output_col.activator_tracked_poly(),
        ) {
            (Some(left_act), _) => Some(left_act),
            (None, existing) => existing,
        };
        let output_col = TrackedCol::new(
            raw_output_col.data_tracked_poly(),
            output_activator,
            raw_output_col.field_ref(),
        );
        let binary_expr_piop_prover_input: BinaryExprPIOPProverInput<F, MvPCS, UvPCS> =
            BinaryExprPIOPProverInput {
                op,
                left_col,
                right_col,
                output_col,
            };
        BinaryExprPIOP::<F, MvPCS, UvPCS>::prove(prover, binary_expr_piop_prover_input)
    }
}

#[derive(Clone)]
pub struct VerifierBinaryExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub node_id: NodeId,
    pub left_proof_plan: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub right_proof_plan: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub hint_generation_plans: IndexMap<String, LogicalPlan>,
}

impl<F, MvPCS, UvPCS> VerifierBinaryExprNode<F, MvPCS, UvPCS>
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

impl<F, MvPCS, UvPCS> VerifierBinaryExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn build_witness_plans(
        bin_expr: BinaryExpr,
        input_plan: LogicalPlan,
    ) -> IndexMap<String, LogicalPlan> {
        if Self::requires_materialized_witness(bin_expr.op) {
            let bool_expr = Expr::BinaryExpr(bin_expr).alias(OUTPUT_PLAN_KEY);
            let bool_plan = LogicalPlanBuilder::from(input_plan.clone())
                .project(vec![bool_expr.clone(), col(ACTIVATOR_COL_NAME)])
                .unwrap()
                .build()
                .unwrap();
            let one = Expr::Literal(datafusion::scalar::ScalarValue::Int64(Some(1)));
            let zero = Expr::Literal(datafusion::scalar::ScalarValue::Int64(Some(0)));

            let selector = case(datafusion::prelude::col(OUTPUT_PLAN_KEY))
                .when(
                    Expr::Literal(datafusion::scalar::ScalarValue::Boolean(Some(true))),
                    one.clone(),
                )
                .otherwise(zero.clone())
                .unwrap()
                .alias(OUTPUT_PLAN_KEY);

            let plan = LogicalPlanBuilder::from(bool_plan)
                .project(vec![selector, col(ACTIVATOR_COL_NAME)])
                .unwrap()
                .build()
                .unwrap();

            IndexMap::from([(String::from(OUTPUT_PLAN_KEY), plan)])
        } else {
            IndexMap::new()
        }
    }
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for VerifierBinaryExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        vec![&self.left_proof_plan, &self.right_proof_plan]
    }
    fn hint_generation_plans(&self) -> IndexMap<String, LogicalPlan> {
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
        piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
        if let Expr::BinaryExpr(bin_expr) = self.node_id.to_expr().unwrap() {
            if !Self::requires_materialized_witness(bin_expr.op) {
                let log_size = piop_tree
                    .tracked_table_oracle(&self.left_proof_plan.node_id(), OUTPUT_PLAN_KEY)
                    .unwrap()
                    .log_size();
                let left_col = piop_tree
                    .tracked_table_oracle(&self.left_proof_plan.node_id(), OUTPUT_PLAN_KEY)
                    .unwrap()
                    .tracked_col_oracle_by_ind(0)
                    .clone();
                let right_col = piop_tree
                    .tracked_table_oracle(&self.right_proof_plan.node_id(), OUTPUT_PLAN_KEY)
                    .unwrap()
                    .tracked_col_oracle_by_ind(0)
                    .clone();
                let output_data_tracked_poly = match bin_expr.op {
                    Operator::And => {
                        let data_mult =
                            &left_col.data_tracked_oracle() * &right_col.data_tracked_oracle();

                        match (
                            left_col.activator_tracked_oracle(),
                            right_col.activator_tracked_oracle(),
                        ) {
                            (Some(l), Some(r)) => &(&l * &r) * &data_mult,
                            (Some(l), None) => &l * &data_mult,
                            (None, Some(r)) => &r * &data_mult,
                            (None, None) => data_mult,
                        }
                    },
                    _ => panic!("unsupported operator for virtual witness"),
                };
                let field_ref = FieldRef::new(Field::new(
                    "output",
                    datafusion::arrow::datatypes::DataType::BinaryView,
                    false,
                ));
                let output_activator = match (
                    left_col.activator_tracked_oracle(),
                    right_col.activator_tracked_oracle(),
                ) {
                    (Some(l), Some(r)) => {
                        debug_assert_eq!(l, r, "AND expects matching activators");
                        Some(l)
                    },
                    (Some(l), None) => Some(l),
                    (None, Some(r)) => Some(r),
                    (None, None) => None,
                };
                let mut tracked_oracles =
                    IndexMap::from_iter(vec![(field_ref.clone(), output_data_tracked_poly)]);
                if let Some(activator_oracle) = output_activator {
                    let activator_field = FieldRef::new(Field::new(
                        arithmetic::ACTIVATOR_COL_NAME,
                        datafusion::arrow::datatypes::DataType::Boolean,
                        true,
                    ));
                    tracked_oracles.insert(activator_field, activator_oracle);
                }
                let output_table = TrackedTableOracle::new(None, tracked_oracles, log_size);
                piop_tree.add_tracked_table_oracle(
                    self.node_id.clone(),
                    OUTPUT_PLAN_KEY.to_string(),
                    output_table,
                );
            }
        }
    }
    fn verify_piop(
        &self,
        verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let op = match self.node_id.to_expr().unwrap() {
            Expr::BinaryExpr(b) => b.op,
            _ => panic!("expected binary expression"),
        };
        let left_col = piop_tree
            .tracked_table_oracle(&self.left_proof_plan.node_id(), OUTPUT_PLAN_KEY)
            .unwrap()
            .tracked_col_oracle_by_ind(0)
            .clone();
        let right_col = piop_tree
            .tracked_table_oracle(&self.right_proof_plan.node_id(), OUTPUT_PLAN_KEY)
            .unwrap()
            .tracked_col_oracle_by_ind(0)
            .clone();

        let raw_output_col = piop_tree
            .tracked_table_oracle(&self.node_id, OUTPUT_PLAN_KEY)
            .unwrap()
            .tracked_col_oracle_by_ind(0)
            .clone();
        let output_activator = match (
            left_col.activator_tracked_oracle(),
            raw_output_col.activator_tracked_oracle(),
        ) {
            (Some(left_act), _) => Some(left_act),
            (None, existing) => existing,
        };
        let output_col = TrackedColOracle::new(
            raw_output_col.data_tracked_oracle(),
            output_activator,
            raw_output_col.field_ref(),
        );
        let binary_expr_piop_verifier_input: BinaryExprPIOPVerifierInput<F, MvPCS, UvPCS> =
            BinaryExprPIOPVerifierInput {
                op,
                left_col_oracle: left_col,
                right_col_oracle: right_col,
                output_col_oracle: output_col,
            };
        BinaryExprPIOP::<F, MvPCS, UvPCS>::verify(verifier, binary_expr_piop_verifier_input)
    }
}

use crate::{
    proof_nodes::{
        OUTPUT_PLAN_KEY,
        cost::ProvingCost,
        id::NodeId,
        prover::{ProverNode, output_prover_logical_plan},
        verifier::{VerifierNode, output_verifier_logical_plan},
    },
    prover::trees::{piop_tree::ProverPIOPTree, proof_tree::ProverProofTree},
    verifier::trees::{piop_tree::VerifierPIOPTree, proof_tree::VerifierProofTree},
};

use arithmetic::{
    ACTIVATOR_COL_NAME, col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
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
    prelude::col,
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
    pub left_prover_node: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub right_prover_node: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub hint_generation_plans: IndexMap<String, (LogicalPlan, bool)>,
}
#[derive(Clone)]
pub struct VerifierBinaryExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub node_id: NodeId,
    pub left_verifier_node: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub right_verifier_node: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub hint_generation_plans: IndexMap<String, (LogicalPlan, bool)>,
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
        vec![&self.left_prover_node, &self.right_prover_node]
    }
    fn hint_generation_plans(&self) -> IndexMap<String, (LogicalPlan, bool)> {
        self.hint_generation_plans.clone()
    }

    fn from_expr(
        ctx: &datafusion::prelude::SessionContext,
        prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        let bin_expr = match expr.clone() {
            Expr::BinaryExpr(b) => b,
            _ => panic!("expected binary expression"),
        };

        let node_id = NodeId::Expr(expr.clone());
        let left_expr = bin_expr.left.as_ref().clone();
        let left_prover_node = ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
            ctx,
            prover_ctx.clone(),
            left_expr.clone(),
            &node_id.clone(),
        )
        .root();
        let right_expr = bin_expr.right.as_ref().clone();
        let right_prover_node = ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
            ctx,
            prover_ctx.clone(),
            right_expr.clone(),
            &node_id.clone(),
        )
        .root();
        let hint_generation_plans = Self::build_hint_generation_plans(
            bin_expr.clone(),
            &left_prover_node,
            &right_prover_node,
        );

        Self {
            node_id: node_id.clone(),
            left_prover_node,
            right_prover_node,
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
                    .tracked_table(&self.left_prover_node.node_id(), OUTPUT_PLAN_KEY)
                    .unwrap()
                    .log_size();
                let left_col = piop_tree
                    .tracked_table(&self.left_prover_node.node_id(), OUTPUT_PLAN_KEY)
                    .unwrap()
                    .tracked_col_by_ind(0)
                    .clone();
                let right_col = piop_tree
                    .tracked_table(&self.right_prover_node.node_id(), OUTPUT_PLAN_KEY)
                    .unwrap()
                    .tracked_col_by_ind(0)
                    .clone();
                let output_data_tracked_poly = match bin_expr.op {
                    Operator::And => {
                        let data_out =
                            &left_col.data_tracked_poly() * &right_col.data_tracked_poly();

                        match (
                            left_col.activator_tracked_poly(),
                            right_col.activator_tracked_poly(),
                        ) {
                            (Some(l), Some(r)) => &(&l * &r) * &data_out,
                            (Some(l), None) => &l * &data_out,
                            (None, Some(r)) => &r * &data_out,
                            (None, None) => data_out,
                        }
                    },
                    Operator::Plus => {
                        let data_out =
                            &left_col.data_tracked_poly() + &right_col.data_tracked_poly();

                        match (
                            left_col.activator_tracked_poly(),
                            right_col.activator_tracked_poly(),
                        ) {
                            (Some(l), Some(r)) => &(&l * &r) * &data_out,
                            (Some(l), None) => &l * &data_out,
                            (None, Some(r)) => &r * &data_out,
                            (None, None) => data_out,
                        }
                    },
                    Operator::Minus => {
                        let data_out =
                            &left_col.data_tracked_poly() - &right_col.data_tracked_poly();

                        match (
                            left_col.activator_tracked_poly(),
                            right_col.activator_tracked_poly(),
                        ) {
                            (Some(l), Some(r)) => &(&l * &r) * &data_out,
                            (Some(l), None) => &l * &data_out,
                            (None, Some(r)) => &r * &data_out,
                            (None, None) => data_out,
                        }
                    },
                    Operator::Multiply => {
                        let data_out =
                            &left_col.data_tracked_poly() * &right_col.data_tracked_poly();

                        match (
                            left_col.activator_tracked_poly(),
                            right_col.activator_tracked_poly(),
                        ) {
                            (Some(l), Some(r)) => &(&l * &r) * &data_out,
                            (Some(l), None) => &l * &data_out,
                            (None, Some(r)) => &r * &data_out,
                            (None, None) => data_out,
                        }
                    },
                    _ => panic!("unsupported operator for virtual witness"),
                };
                let field_ref = if let Some(f) = left_col.field_ref() {
                    f.clone()
                } else {
                    FieldRef::new(Field::new(
                        "output",
                        datafusion::arrow::datatypes::DataType::Null,
                        false,
                    ))
                };
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
            .tracked_table(&self.left_prover_node.node_id(), OUTPUT_PLAN_KEY)
            .unwrap()
            .tracked_col_by_ind(0)
            .clone();
        let right_col = piop_tree
            .tracked_table(&self.right_prover_node.node_id(), OUTPUT_PLAN_KEY)
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

    fn build_hint_generation_plans(
        bin_expr: BinaryExpr,
        left_node: &Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
        right_node: &Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    ) -> IndexMap<String, (LogicalPlan, bool)> {
        let left_plan = output_prover_logical_plan::<F, MvPCS, UvPCS>(left_node);
        let right_plan = output_prover_logical_plan::<F, MvPCS, UvPCS>(right_node);
        let base_plan = left_plan
            .clone()
            .or(right_plan.clone())
            .expect("binary expression requires at least one child output plan");

        let include_activator = base_plan
            .schema()
            .field_with_unqualified_name(ACTIVATOR_COL_NAME)
            .is_ok();

        let binary_expr = Expr::BinaryExpr(*Box::new(bin_expr.clone())).alias("binary_expr");

        let mut projection_exprs = vec![binary_expr];
        if include_activator {
            projection_exprs.push(col(ACTIVATOR_COL_NAME));
        }

        let output_plan = LogicalPlanBuilder::from(base_plan)
            .project(projection_exprs)
            .expect("failed to project binary expression output")
            .build()
            .expect("failed to build binary expression logical plan");

        IndexMap::from([(
            OUTPUT_PLAN_KEY.to_string(),
            (
                output_plan,
                Self::requires_materialized_witness(bin_expr.op),
            ),
        )])
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
        vec![&self.left_verifier_node, &self.right_verifier_node]
    }
    fn hint_generation_plans(&self) -> IndexMap<String, (LogicalPlan, bool)> {
        self.hint_generation_plans.clone()
    }

    fn from_expr(
        ctx: &datafusion::prelude::SessionContext,
        prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        let bin_expr = match expr.clone() {
            Expr::BinaryExpr(b) => b,
            _ => panic!("expected binary expression"),
        };
        let node_id = NodeId::Expr(expr.clone());
        let left_expr = bin_expr.left.as_ref().clone();
        let left_verifier_node = VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
            ctx,
            prover_ctx.clone(),
            left_expr.clone(),
            &node_id.clone(),
        )
        .root();
        let right_expr = bin_expr.right.as_ref().clone();
        let right_verifier_node = VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
            ctx,
            prover_ctx.clone(),
            right_expr.clone(),
            &node_id.clone(),
        )
        .root();
        let hint_generation_plans = Self::build_hint_generation_plans(
            bin_expr.clone(),
            &left_verifier_node,
            &right_verifier_node,
        );

        Self {
            node_id,
            left_verifier_node,
            right_verifier_node,
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
                    .tracked_table_oracle(&self.left_verifier_node.node_id(), OUTPUT_PLAN_KEY)
                    .unwrap()
                    .log_size();
                let left_col = piop_tree
                    .tracked_table_oracle(&self.left_verifier_node.node_id(), OUTPUT_PLAN_KEY)
                    .unwrap()
                    .tracked_col_oracle_by_ind(0)
                    .clone();
                let right_col = piop_tree
                    .tracked_table_oracle(&self.right_verifier_node.node_id(), OUTPUT_PLAN_KEY)
                    .unwrap()
                    .tracked_col_oracle_by_ind(0)
                    .clone();
                let output_data_tracked_poly = match bin_expr.op {
                    Operator::And => {
                        let data_out =
                            &left_col.data_tracked_oracle() * &right_col.data_tracked_oracle();

                        match (
                            left_col.activator_tracked_oracle(),
                            right_col.activator_tracked_oracle(),
                        ) {
                            (Some(l), Some(r)) => &(&l * &r) * &data_out,
                            (Some(l), None) => &l * &data_out,
                            (None, Some(r)) => &r * &data_out,
                            (None, None) => data_out,
                        }
                    },
                    Operator::Plus => {
                        let data_out =
                            &left_col.data_tracked_oracle() + &right_col.data_tracked_oracle();

                        match (
                            left_col.activator_tracked_oracle(),
                            right_col.activator_tracked_oracle(),
                        ) {
                            (Some(l), Some(r)) => &(&l * &r) * &data_out,
                            (Some(l), None) => &l * &data_out,
                            (None, Some(r)) => &r * &data_out,
                            (None, None) => data_out,
                        }
                    },
                    Operator::Minus => {
                        let data_out =
                            &left_col.data_tracked_oracle() - &right_col.data_tracked_oracle();

                        match (
                            left_col.activator_tracked_oracle(),
                            right_col.activator_tracked_oracle(),
                        ) {
                            (Some(l), Some(r)) => &(&l * &r) * &data_out,
                            (Some(l), None) => &l * &data_out,
                            (None, Some(r)) => &r * &data_out,
                            (None, None) => data_out,
                        }
                    },
                    Operator::Multiply => {
                        let data_out =
                            &left_col.data_tracked_oracle() * &right_col.data_tracked_oracle();

                        match (
                            left_col.activator_tracked_oracle(),
                            right_col.activator_tracked_oracle(),
                        ) {
                            (Some(l), Some(r)) => &(&l * &r) * &data_out,
                            (Some(l), None) => &l * &data_out,
                            (None, Some(r)) => &r * &data_out,
                            (None, None) => data_out,
                        }
                    },
                    _ => panic!("unsupported operator for virtual witness"),
                };

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
                let field_ref = if let Some(f) = left_col.field_ref() {
                    f.clone()
                } else {
                    FieldRef::new(Field::new(
                        "output",
                        datafusion::arrow::datatypes::DataType::Null,
                        false,
                    ))
                };
                let mut tracked_oracles =
                    IndexMap::from_iter(vec![(field_ref, output_data_tracked_poly)]);
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
            .tracked_table_oracle(&self.left_verifier_node.node_id(), OUTPUT_PLAN_KEY)
            .unwrap()
            .tracked_col_oracle_by_ind(0)
            .clone();
        let right_col = piop_tree
            .tracked_table_oracle(&self.right_verifier_node.node_id(), OUTPUT_PLAN_KEY)
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
    fn build_hint_generation_plans(
        bin_expr: BinaryExpr,
        left_node: &Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
        right_node: &Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    ) -> IndexMap<String, (LogicalPlan, bool)> {
        dbg!(left_node.name(), right_node.name());
        let left_plan = output_verifier_logical_plan::<F, MvPCS, UvPCS>(left_node);
        let right_plan = output_verifier_logical_plan::<F, MvPCS, UvPCS>(right_node);

        let base_plan = left_plan
            .clone()
            .or(right_plan.clone())
            .expect("binary expression requires at least one child output plan");

        let include_activator = base_plan
            .schema()
            .field_with_unqualified_name(ACTIVATOR_COL_NAME)
            .is_ok();

        let binary_expr = Expr::BinaryExpr(*Box::new(bin_expr.clone())).alias("binary_expr");

        let mut projection_exprs = vec![binary_expr];
        if include_activator {
            projection_exprs.push(col(ACTIVATOR_COL_NAME));
        }

        let output_plan = LogicalPlanBuilder::from(base_plan)
            .project(projection_exprs)
            .expect("failed to project binary expression output")
            .build()
            .expect("failed to build binary expression logical plan");

        IndexMap::from([(
            OUTPUT_PLAN_KEY.to_string(),
            (
                output_plan,
                Self::requires_materialized_witness(bin_expr.op),
            ),
        )])
    }
}

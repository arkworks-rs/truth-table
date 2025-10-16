use crate::{
    proof_nodes::{
        OUTPUT_PLAN_KEY, cost::ProvingCost, id::NodeId, prover::ProverNode, verifier::VerifierNode,
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
    logical_expr::{Expr, LogicalPlan, LogicalPlanBuilder, Operator},
    prelude::col,
};
use indexmap::IndexMap;
use ra_toolbox::expr_piop::binary_expr::{
    BinaryExprPIOP, BinaryExprPIOPProverInput, BinaryExprPIOPVerifierInput,
};
use std::sync::Arc;
mod virtual_ops;
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
    pub parent_node_id: NodeId,
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
    pub parent_node_id: NodeId,
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
    fn hint_generation_plans(
        &self,
        proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, (LogicalPlan, bool)> {
        // Extract the binary expression from the node ID
        let bin_expr = match self.node_id.to_expr().unwrap() {
            Expr::BinaryExpr(b) => b.clone(),
            _ => panic!("expected binary expression"),
        };

        // Get a base plan to compute the expr, which is the first tablescan plan we
        // find. We might run into a problem in join scenarios where the left
        // and right nodes come from different base plans.
        let Some(base_table_scan_plan) = first_tablescan_plan_prover(proof_tree) else {
            panic!("no tablescan plan found");
        };

        // Build the projection expressions for the binary expression
        // This determines the output schema of this node
        // This projection, projects the expression result and the activator
        let mut projection_exprs =
            vec![Expr::BinaryExpr(*Box::new(bin_expr.clone())).alias("binary_expr")];
        if base_table_scan_plan
            .schema()
            .field_with_unqualified_name(ACTIVATOR_COL_NAME)
            .is_ok()
        {
            projection_exprs.push(col(ACTIVATOR_COL_NAME));
        } else {
            panic!("base plan missing activator column");
        }

        // Build the output plan
        let output_plan = LogicalPlanBuilder::from(base_table_scan_plan)
            .project(projection_exprs)
            .unwrap()
            .build()
            .unwrap();

        IndexMap::from([(
            OUTPUT_PLAN_KEY.to_string(),
            (
                output_plan,
                Self::requires_materialized_witness(bin_expr.op),
            ),
        )])
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
        // Get the Binary Expression
        let bin_expr = match expr.clone() {
            Expr::BinaryExpr(b) => b,
            _ => panic!("expected binary expression"),
        };

        // Builf the id for the current node
        let node_id = NodeId::Expr(expr.clone());
        // Recursively build the left child node
        let left_expr = bin_expr.left.as_ref().clone();
        let left_prover_node = ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
            ctx,
            prover_ctx.clone(),
            left_expr.clone(),
            &node_id,
        )
        .root();
        // Recursively build the right child node
        let right_expr = bin_expr.right.as_ref().clone();
        let right_prover_node = ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
            ctx,
            prover_ctx.clone(),
            right_expr.clone(),
            &node_id,
        )
        .root();

        Self {
            node_id,
            left_prover_node,
            right_prover_node,
            parent_node_id,
        }
    }

    fn cost(
        &self,
        _statistics: datafusion::common::Statistics,
        _schema: datafusion::arrow::datatypes::SchemaRef,
    ) -> ProvingCost {
        todo!()
    }

    fn ctx_schema(
        &self,
        proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> datafusion::arrow::datatypes::SchemaRef {
        proof_tree
            .node(&self.parent_node_id)
            .unwrap()
            .ctx_schema(proof_tree)
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

                piop_tree.add_table(
                    self.node_id.clone(),
                    OUTPUT_PLAN_KEY.to_string(),
                    Self::output_virtual_table(bin_expr, &left_col, &right_col, log_size),
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
    fn hint_generation_plans(
        &self,
        proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, (LogicalPlan, bool)> {
        // Extract the binary expression from the node ID
        let bin_expr = match self.node_id.to_expr().unwrap() {
            Expr::BinaryExpr(b) => b.clone(),
            _ => panic!("expected binary expression"),
        };
        // Get a base plan to compute the expr, which is the first tablescan plan we
        // find. We might run into a problem in join scenarios where the left
        // and right nodes come from different base plans.
        let Some(base_table_scan_plan) = first_tablescan_plan_verifier(proof_tree) else {
            panic!("no tablescan plan found");
        };

        // Build the projection expressions for the binary expression
        // This determines the output schema of this node
        // This projection, projects the expression result and the activator
        let mut projection_exprs =
            vec![Expr::BinaryExpr(*Box::new(bin_expr.clone())).alias("binary_expr")];
        if base_table_scan_plan
            .schema()
            .field_with_unqualified_name(ACTIVATOR_COL_NAME)
            .is_ok()
        {
            projection_exprs.push(col(ACTIVATOR_COL_NAME));
        }
        // Build the output plan
        let output_plan = LogicalPlanBuilder::from(base_table_scan_plan)
            .project(projection_exprs)
            .unwrap()
            .build()
            .unwrap();

        IndexMap::from([(
            OUTPUT_PLAN_KEY.to_string(),
            (
                output_plan,
                Self::requires_materialized_witness(bin_expr.op),
            ),
        )])
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
        // Get the Binary Expression
        let bin_expr = match expr.clone() {
            Expr::BinaryExpr(b) => b,
            _ => panic!("expected binary expression"),
        };
        // Builf the id for the current node
        let node_id = NodeId::Expr(expr.clone());
        // Recursively build the left child node
        let left_expr = bin_expr.left.as_ref().clone();
        let left_verifier_node = VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
            ctx,
            prover_ctx.clone(),
            left_expr.clone(),
            &node_id,
        )
        .root();
        // Recursively build the right child node

        let right_expr = bin_expr.right.as_ref().clone();
        let right_verifier_node = VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
            ctx,
            prover_ctx.clone(),
            right_expr.clone(),
            &node_id,
        )
        .root();

        Self {
            node_id,
            left_verifier_node,
            right_verifier_node,
            parent_node_id,
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
                let left_col_oracle = piop_tree
                    .tracked_table_oracle(&self.left_verifier_node.node_id(), OUTPUT_PLAN_KEY)
                    .unwrap()
                    .tracked_col_oracle_by_ind(0)
                    .clone();
                let right_col_oracle = piop_tree
                    .tracked_table_oracle(&self.right_verifier_node.node_id(), OUTPUT_PLAN_KEY)
                    .unwrap()
                    .tracked_col_oracle_by_ind(0)
                    .clone();

                piop_tree.add_tracked_table_oracle(
                    self.node_id.clone(),
                    OUTPUT_PLAN_KEY.to_string(),
                    Self::output_virtual_table(
                        bin_expr,
                        &left_col_oracle,
                        &right_col_oracle,
                        log_size,
                    ),
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

    fn ctx_schema(
        &self,
        proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> datafusion::arrow::datatypes::SchemaRef {
        proof_tree
            .node(&self.parent_node_id)
            .unwrap()
            .ctx_schema(proof_tree)
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
}

fn first_tablescan_plan_prover<F, MvPCS, UvPCS>(
    proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
) -> Option<LogicalPlan>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    proof_tree
        .proof_nodes()
        .iter()
        .find_map(|(node_id, node)| match node_id {
            NodeId::LP(LogicalPlan::TableScan(_)) => node
                .hint_generation_plans(proof_tree)
                .get(OUTPUT_PLAN_KEY)
                .map(|(plan, _)| plan.clone()),
            _ => None,
        })
}

fn first_tablescan_plan_verifier<F, MvPCS, UvPCS>(
    proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
) -> Option<LogicalPlan>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    proof_tree
        .proof_nodes()
        .iter()
        .find_map(|(node_id, node)| match node_id {
            NodeId::LP(LogicalPlan::TableScan(_)) => node
                .hint_generation_plans(proof_tree)
                .get(OUTPUT_PLAN_KEY)
                .map(|(plan, _)| plan.clone()),
            _ => None,
        })
}

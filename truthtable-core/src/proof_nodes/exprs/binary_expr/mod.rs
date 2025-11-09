use crate::proof_nodes::HintGenerationPlan;

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
    verifier::structs::oracle::TrackedOracle,
};
use datafusion::{
    arrow::datatypes::{DataType, Field, FieldRef},
    logical_expr::{Expr, LogicalPlan, LogicalPlanBuilder, Operator},
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
    ) -> IndexMap<String, HintGenerationPlan> {
        // Extract the binary expression from the node ID
        let bin_expr = match self.node_id.to_expr().unwrap() {
            Expr::BinaryExpr(b) => b.clone(),
            _ => panic!("expected binary expression"),
        };
        // Prefer using the ctx LP plan first so joins can reference both sides,
        // then fall back to scanning every table scan in order until projection works.
        let ctx_plan = self
            .ctx_lp_node(proof_tree)
            .hint_generation_plans(proof_tree)
            .get(OUTPUT_PLAN_KEY)
            .map(|hint| hint.plan().clone());
        let table_scan_plans = tablescan_plans_prover(proof_tree);
        let Some(output_plan) =
            build_bin_expr_hint_generation_plans(&bin_expr, ctx_plan, table_scan_plans.into_iter())
        else {
            panic!("no valid plan found for binary expression");
        };
        IndexMap::from([(
            OUTPUT_PLAN_KEY.to_string(),
            if Self::requires_materialized_witness(bin_expr.op) {
                HintGenerationPlan::new_materialized(OUTPUT_PLAN_KEY.to_string(), output_plan)
            } else {
                HintGenerationPlan::new_virtual(OUTPUT_PLAN_KEY.to_string(), output_plan)
            },
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

    fn ctx_lp_node(
        &self,
        proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverNode<F, MvPCS, UvPCS>> {
        proof_tree
            .node(&self.parent_node_id)
            .unwrap()
            .ctx_lp_node(proof_tree)
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
        if let Expr::BinaryExpr(bin_expr) = self.node_id.to_expr().unwrap() {
            let (log_size, left_col) = {
                let table = piop_tree
                    .tracked_table(&self.left_prover_node.node_id(), OUTPUT_PLAN_KEY)
                    .expect("missing left child output for binary expr");
                (table.log_size(), table.tracked_col_by_ind(0).clone())
            };
            let right_col = {
                let table = piop_tree
                    .tracked_table(&self.right_prover_node.node_id(), OUTPUT_PLAN_KEY)
                    .expect("missing right child output for binary expr");
                table.tracked_col_by_ind(0).clone()
            };

            if !Self::requires_materialized_witness(bin_expr.op) {
                piop_tree.add_table(
                    self.node_id.clone(),
                    OUTPUT_PLAN_KEY.to_string(),
                    Self::output_virtual_table(bin_expr, &left_col, &right_col, log_size),
                );
            } else {
                Self::append_activator_to_materialized(
                    piop_tree,
                    &self.node_id,
                    &left_col,
                    &right_col,
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
        BinaryExprPIOP::<F, MvPCS, UvPCS>::prove(prover, binary_expr_piop_prover_input)?;
        Ok(())
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

    fn append_activator_to_materialized(
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
        node_id: &NodeId,
        left_col: &TrackedCol<F, MvPCS, UvPCS>,
        right_col: &TrackedCol<F, MvPCS, UvPCS>,
    ) {
        let Some(existing_output) = piop_tree.tracked_table(node_id, OUTPUT_PLAN_KEY).cloned()
        else {
            return;
        };

        if existing_output
            .tracked_polys()
            .iter()
            .any(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
        {
            return;
        }

        let Some(activator_poly) = Self::combine_activators(
            left_col.activator_tracked_poly(),
            right_col.activator_tracked_poly(),
        ) else {
            return;
        };

        let mut columns: IndexMap<_, _> = existing_output
            .tracked_polys()
            .iter()
            .map(|(field, poly)| (field.clone(), poly.clone()))
            .collect();
        columns.insert(
            Arc::new(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, true)),
            activator_poly,
        );

        let new_table = TrackedTable::new(
            existing_output.schema(),
            columns,
            existing_output.log_size(),
        );

        piop_tree.add_table(node_id.clone(), OUTPUT_PLAN_KEY.to_string(), new_table);
    }

    fn combine_activators(
        left: Option<ark_piop::prover::structs::polynomial::TrackedPoly<F, MvPCS, UvPCS>>,
        right: Option<ark_piop::prover::structs::polynomial::TrackedPoly<F, MvPCS, UvPCS>>,
    ) -> Option<ark_piop::prover::structs::polynomial::TrackedPoly<F, MvPCS, UvPCS>> {
        match (left, right) {
            (Some(l), Some(r)) => Some(&l * &r),
            (Some(l), None) => Some(l),
            (None, Some(r)) => Some(r),
            (None, None) => None,
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
        vec![&self.left_verifier_node, &self.right_verifier_node]
    }
    fn hint_generation_plans(
        &self,
        proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, HintGenerationPlan> {
        // Extract the binary expression from the node ID
        let bin_expr = match self.node_id.to_expr().unwrap() {
            Expr::BinaryExpr(b) => b.clone(),
            _ => panic!("expected binary expression"),
        };
        // Build the projection starting from the ctx LP whenever possible and
        // inspect every table scan only when the ctx LP does not expose the
        // binary expression inputs.
        let ctx_plan = self
            .ctx_lp_node(proof_tree)
            .hint_generation_plans(proof_tree)
            .get(OUTPUT_PLAN_KEY)
            .map(|hint| hint.plan().clone());
        let table_scan_plans = tablescan_plans_verifier(proof_tree);
        let Some(output_plan) =
            build_bin_expr_hint_generation_plans(&bin_expr, ctx_plan, table_scan_plans.into_iter())
        else {
            panic!("no valid plan found for binary expression");
        };

        IndexMap::from([(
            OUTPUT_PLAN_KEY.to_string(),
            if Self::requires_materialized_witness(bin_expr.op) {
                HintGenerationPlan::new_materialized(OUTPUT_PLAN_KEY.to_string(), output_plan)
            } else {
                HintGenerationPlan::new_virtual(OUTPUT_PLAN_KEY.to_string(), output_plan)
            },
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
            let (log_size, left_col_oracle) = {
                let table = piop_tree
                    .tracked_table_oracle(&self.left_verifier_node.node_id(), OUTPUT_PLAN_KEY)
                    .expect("missing left child output oracle for binary expr");
                (table.log_size(), table.tracked_col_oracle_by_ind(0).clone())
            };
            let right_col_oracle = {
                let table = piop_tree
                    .tracked_table_oracle(&self.right_verifier_node.node_id(), OUTPUT_PLAN_KEY)
                    .expect("missing right child output oracle for binary expr");
                table.tracked_col_oracle_by_ind(0).clone()
            };

            if !Self::requires_materialized_witness(bin_expr.op) {
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
            } else {
                Self::append_activator_to_materialized_oracle(
                    piop_tree,
                    &self.node_id,
                    &left_col_oracle,
                    &right_col_oracle,
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
        BinaryExprPIOP::<F, MvPCS, UvPCS>::verify(verifier, binary_expr_piop_verifier_input)?;
        Ok(())
    }

    fn ctx_lp_node(
        &self,
        proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>> {
        proof_tree
            .node(&self.parent_node_id)
            .unwrap()
            .ctx_lp_node(proof_tree)
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

    fn append_activator_to_materialized_oracle(
        piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
        node_id: &NodeId,
        left_col: &TrackedColOracle<F, MvPCS, UvPCS>,
        right_col: &TrackedColOracle<F, MvPCS, UvPCS>,
    ) {
        let Some(existing_output) = piop_tree
            .tracked_table_oracle(node_id, OUTPUT_PLAN_KEY)
            .cloned()
        else {
            return;
        };

        if existing_output
            .tracked_oracles()
            .iter()
            .any(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
        {
            return;
        }

        let Some(activator_oracle) = Self::combine_oracle_activators(
            left_col.activator_tracked_oracle(),
            right_col.activator_tracked_oracle(),
        ) else {
            return;
        };

        let mut columns: IndexMap<_, _> = existing_output
            .tracked_oracles()
            .iter()
            .map(|(field, oracle)| (field.clone(), oracle.clone()))
            .collect();
        columns.insert(
            Arc::new(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, true)),
            activator_oracle,
        );

        let new_table = TrackedTableOracle::new(
            existing_output.schema(),
            columns,
            existing_output.log_size(),
        );

        piop_tree.add_tracked_table_oracle(node_id.clone(), OUTPUT_PLAN_KEY.to_string(), new_table);
    }

    fn combine_oracle_activators(
        left: Option<TrackedOracle<F, MvPCS, UvPCS>>,
        right: Option<TrackedOracle<F, MvPCS, UvPCS>>,
    ) -> Option<TrackedOracle<F, MvPCS, UvPCS>> {
        match (left, right) {
            (Some(l), Some(r)) => Some(&l * &r),
            (Some(l), None) => Some(l),
            (None, Some(r)) => Some(r),
            (None, None) => None,
        }
    }
}

fn build_bin_expr_hint_generation_plans(
    bin_expr: &datafusion::logical_expr::BinaryExpr,
    ctx_plan: Option<LogicalPlan>,
    table_scan_plans: impl Iterator<Item = LogicalPlan>,
) -> Option<LogicalPlan> {
    // Try projecting over the ctx LP first (if available) and then scan each
    // table scan output until the projection succeeds. This mirrors how column
    // resolution walks through the context before visiting every scan.
    let mut candidate_plans = ctx_plan.into_iter().collect::<Vec<_>>();
    candidate_plans.extend(table_scan_plans);

    for plan in candidate_plans {
        let projection_exprs =
            vec![Expr::BinaryExpr(*Box::new(bin_expr.clone())).alias("binary_expr")];
        let projection_result = LogicalPlanBuilder::from(plan)
            .project(projection_exprs)
            .and_then(|builder| builder.build());

        if let Ok(built_plan) = projection_result {
            return Some(built_plan);
        }
    }

    None
}

fn tablescan_plans_prover<F, MvPCS, UvPCS>(
    proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
) -> Vec<LogicalPlan>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    proof_tree
        .arena()
        .iter()
        .filter_map(|(node_id, node)| match node_id {
            NodeId::LP(LogicalPlan::TableScan(_)) => node
                .hint_generation_plans(proof_tree)
                .get(OUTPUT_PLAN_KEY)
                .map(|hint| hint.plan().clone()),
            _ => None,
        })
        .collect()
}

fn tablescan_plans_verifier<F, MvPCS, UvPCS>(
    proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
) -> Vec<LogicalPlan>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    proof_tree
        .arena()
        .iter()
        .filter_map(|(node_id, node)| match node_id {
            NodeId::LP(LogicalPlan::TableScan(_)) => node
                .hint_generation_plans(proof_tree)
                .get(OUTPUT_PLAN_KEY)
                .map(|hint| hint.plan().clone()),
            _ => None,
        })
        .collect()
}

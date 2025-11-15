use crate::{
    proof_nodes::{
        HintGenerationPlan, OUTPUT_PLAN_KEY, cost::ProvingCost, id::NodeId, prover::{ProverExprNode, ProverNode},
        verifier::{VerifierExprNode, VerifierNode},
    },
    prover::trees::{piop_tree::ProverPIOPTree, proof_tree::ProverProofTree},
    verifier::trees::{piop_tree::VerifierPIOPTree, proof_tree::VerifierProofTree},
};
use arithmetic::{
    ACTIVATOR_COL_NAME, col::TrackedCol, col_oracle::TrackedColOracle, ctx::SharedCtx,
    table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    verifier::structs::oracle::TrackedOracle,
};
use datafusion::{
    arrow::datatypes::FieldRef,
    logical_expr::{Expr, LogicalPlan, LogicalPlanBuilder},
    prelude::SessionContext,
};
use datafusion::prelude::DataFrame;

use indexmap::IndexMap;
use std::sync::Arc;
#[derive(Clone)]
pub struct ProverColumnExprNode {
    pub parent_node_id: NodeId,
    pub node_id: NodeId,
}
#[derive(Clone)]
pub struct VerifierColumnExprNode {
    pub parent_node_id: NodeId,
    pub node_id: NodeId,
}
/// Human-friendly detail string for a column expression, including its table
/// reference when present.
pub fn format_column_detail(column: &datafusion::common::Column) -> String {
    match column.relation.as_ref() {
        Some(relation) => format!("{} (table_ref = {})", column.flat_name(), relation),
        None => column.flat_name(),
    }
}
impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for ProverColumnExprNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn hint_generation_plans(
        &self,
        proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> indexmap::IndexMap<String, DataFrame> {
        todo!()
    }


    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        Vec::new()
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
        todo!()
    }


    fn add_virtual_witness(
        &self,
        piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }

    fn arithmetic_post_process(
        &self,
        _arithmetized_tree: &mut crate::prover::trees::arithmetized_tree::ProverArithmetizedTree<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }

    fn output_data_frame(
        &self,
        _proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> DataFrame {
        todo!()
    }

    fn is_public(&self) -> bool {
        todo!()
    }

    fn prove_piop(
        &self,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> ark_piop::errors::SnarkResult<()> {
        todo!()
    }

}

impl<F, MvPCS, UvPCS> ProverExprNode<F, MvPCS, UvPCS> for ProverColumnExprNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_expr(
        _ctx: &SessionContext,
        _prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        Self {
            node_id: NodeId::Expr(expr),
            parent_node_id,
        }
    }
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for VerifierColumnExprNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn hint_generation_plans(
        &self,
        _proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> indexmap::IndexMap<String, DataFrame> {
        todo!()
    }


    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        Vec::new()
    }


    fn add_virtual_witness(
        &self,
        _piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }



    fn ctx_lp_node(
        &self,
        _proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>> {
        todo!()
    }



    fn verify_piop(
        &self,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> ark_piop::errors::SnarkResult<()> {
        todo!()
    }


    fn output_data_frame(
        &self,
        _proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> DataFrame {
        todo!()
    }


    fn is_public(&self) -> bool {
        todo!()
    }

}

impl<F, MvPCS, UvPCS> VerifierExprNode<F, MvPCS, UvPCS> for VerifierColumnExprNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_expr(
        _ctx: &SessionContext,
        _verifier_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        Self {
            node_id: NodeId::Expr(expr),
            parent_node_id,
        }
    }
}


impl ProverColumnExprNode {
    fn resolve_col<F, MvPCS, UvPCS>(
        &self,
        column_expr: &datafusion::common::Column,
        piop_tree: &ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> TrackedCol<F, MvPCS, UvPCS>
    where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>> + 'static,
        UvPCS: PCS<F, Poly = LDE<F>> + 'static,
    {
        let ctx_lp_node = self.ctx_lp_node(piop_tree.proof_tree());
        if let Some(table) = piop_tree.tracked_table(&ctx_lp_node.node_id(), OUTPUT_PLAN_KEY)
            && let Some(col) = table.tracked_col_by_name(&column_expr.name)
        {
            return col;
        }

        if let Some(relation) = &column_expr.relation {
            for (node_id, _) in piop_tree.proof_tree().arena().iter() {
                let matches_reference = match node_id {
                    NodeId::LP(LogicalPlan::TableScan(scan_plan)) => {
                        relation.resolved_eq(&scan_plan.table_name)
                    }
                    NodeId::LP(LogicalPlan::SubqueryAlias(alias_plan)) => {
                        relation.resolved_eq(&alias_plan.alias)
                    }
                    _ => false,
                };

                if !matches_reference {
                    continue;
                }

                if let Some(table) = piop_tree.tracked_table(node_id, OUTPUT_PLAN_KEY)
                    && let Some(col) = table.tracked_col_by_name(&column_expr.name)
                {
                    return col;
                }
            }
        }

        panic!(
            "column {} not found in execution context",
            format_column_detail(column_expr)
        );
    }
}

impl VerifierColumnExprNode {
    fn resolve_col_oracle<F, MvPCS, UvPCS>(
        &self,
        column_expr: &datafusion::common::Column,
        piop_tree: &VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> TrackedColOracle<F, MvPCS, UvPCS>
    where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>> + 'static,
        UvPCS: PCS<F, Poly = LDE<F>> + 'static,
    {
        let ctx_lp_node = self.ctx_lp_node(piop_tree.proof_tree());
        if let Some(table) = piop_tree.tracked_table_oracle(&ctx_lp_node.node_id(), OUTPUT_PLAN_KEY)
            && let Some(col) = table.tracked_col_oracle_by_name(&column_expr.name)
        {
            return col;
        }

        if let Some(relation) = &column_expr.relation {
            for (node_id, _) in piop_tree.proof_tree().arena().iter() {
                let matches_reference = match node_id {
                    NodeId::LP(LogicalPlan::TableScan(scan_plan)) => {
                        relation.resolved_eq(&scan_plan.table_name)
                    }
                    NodeId::LP(LogicalPlan::SubqueryAlias(alias_plan)) => {
                        relation.resolved_eq(&alias_plan.alias)
                    }
                    _ => false,
                };

                if !matches_reference {
                    continue;
                }

                if let Some(table) = piop_tree.tracked_table_oracle(node_id, OUTPUT_PLAN_KEY)
                    && let Some(col) = table.tracked_col_oracle_by_name(&column_expr.name)
                {
                    return col;
                }
            }
        }

        panic!(
            "column {} not found in execution context",
            format_column_detail(column_expr)
        );
    }
}

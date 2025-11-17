use std::sync::Arc;

use arithmetic::{ACTIVATOR_EXPR, ctx::SharedCtx};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{common::Column, prelude::SessionContext};
use datafusion_expr::{Expr, LogicalPlan};

use crate::{
    proof_nodes::{
        HintGenerationPlan,
        lps::projection::ProverProjectionNode,
        prover::{ProverExprNode, ProverGadgetNode, ProverPlanNode},
    },
    prover::trees::proof_tree::ProverProofTree,
    tree::{Node, NodeId, Tree},
};

#[derive(Clone)]
pub struct ProverColumnExprNode {
    pub parent_node_id: NodeId,
    pub column: Column,
}
#[derive(Clone)]
pub struct VerifierColumnExprNode {
    pub parent_node_id: NodeId,
    pub column: Column,
}

impl<F, MvPCS, UvPCS> Node<F, MvPCS, UvPCS> for ProverColumnExprNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn children(&self) -> Vec<Arc<dyn Node<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn node_id(&self) -> NodeId {
        NodeId::Expr(Expr::Column(self.column.clone()))
    }
}

impl<F, MvPCS, UvPCS> ProverGadgetNode<F, MvPCS, UvPCS> for ProverColumnExprNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn hint_generation_plans(
        &self,
        _proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> indexmap::IndexMap<String, crate::proof_nodes::HintGenerationPlan> {
        todo!()
    }

    fn arithmetic_post_process(&self) {
        todo!()
    }

    fn add_virtual_witness(&self, prover: &mut ark_piop::prover::ArgProver<F, MvPCS, UvPCS>) {
        todo!()
    }

    fn prove_piop(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<F, MvPCS, UvPCS>,
    ) -> ark_piop::errors::SnarkResult<()> {
        todo!()
    }

    fn cost(
        &self,
        statistics: datafusion::common::Statistics,
        schema: datafusion::arrow::datatypes::SchemaRef,
    ) -> crate::proof_nodes::cost::ProvingCost {
        todo!()
    }
}

impl<F, MvPCS, UvPCS> ProverPlanNode<F, MvPCS, UvPCS> for ProverColumnExprNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn output(&self, proof_tree: &ProverProofTree<F, MvPCS, UvPCS>) -> HintGenerationPlan {
        let ctx_lp_node = self.ctx_lp_node(proof_tree);
        let base_hint_generation_plan = ctx_lp_node.output(proof_tree);
        let base_data_frame = base_hint_generation_plan.data_frame();
        let projection_exprs = vec![Expr::Column(self.column.clone()), ACTIVATOR_EXPR.clone()];
        let projected_data_frame = base_data_frame.clone().select(projection_exprs).unwrap();
        HintGenerationPlan::new_virtual(projected_data_frame)
    }

    fn ctx_lp_node(
        &self,
        proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>> {
        proof_tree
            .get_node(&self.parent_node_id)
            .unwrap()
            .ctx_lp_node(proof_tree)
    }
}

impl<F, MvPCS, UvPCS> ProverExprNode<F, MvPCS, UvPCS> for ProverColumnExprNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn from_expr(
        _ctx: &SessionContext,
        _prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        _expr: datafusion::logical_expr::Expr,
        parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        let column = match _expr {
            Expr::Column(col) => col,
            _ => panic!(),
        };
        Self {
            parent_node_id,
            column,
        }
    }
}

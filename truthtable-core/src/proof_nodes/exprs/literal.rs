use std::sync::Arc;

use arithmetic::ctx::SharedCtx;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion_common::ScalarValue;
use datafusion_expr::Expr;

use crate::tree::{Node, NodeId};

#[derive(Clone)]
pub struct ProverLiteralExprNode {
    pub literal: ScalarValue,
    pub parent_node_id: NodeId,
}

impl<F, MvPCS, UvPCS> Node<F, MvPCS, UvPCS> for ProverLiteralExprNode
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn children(&self) -> Vec<Arc<dyn Node<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn node_id(&self) -> NodeId {
        NodeId::Expr(Expr::Literal(self.literal.clone()))
    }
}

impl<F, MvPCS, UvPCS> crate::proof_nodes::prover::ProverPlanNode<F, MvPCS, UvPCS>
    for ProverLiteralExprNode
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn hint_dfs(
        &self,
        _proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> indexmap::IndexMap<String, crate::proof_nodes::HintDF> {
        indexmap::IndexMap::new()
    }

    fn output(
        &self,
        _proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> crate::proof_nodes::HintDF {
        todo!()
    }

    fn ctx_lp_node(
        &self,
        proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> std::sync::Arc<dyn crate::proof_nodes::prover::ProverPlanNode<F, MvPCS, UvPCS>> {
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
        statistics: datafusion_common::Statistics,
        schema: datafusion::arrow::datatypes::SchemaRef,
    ) -> crate::proof_nodes::cost::ProvingCost {
        todo!()
    }
}

impl<F, MvPCS, UvPCS> crate::proof_nodes::prover::ProverExprNode<F, MvPCS, UvPCS>
    for ProverLiteralExprNode
where
    F: ark_ff::PrimeField,
    MvPCS: ark_piop::pcs::PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: ark_piop::pcs::PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn from_expr(
        ctx: &datafusion::execution::context::SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        expr: datafusion_expr::Expr,
        parent_node_id: NodeId,
    ) -> Self {
        let literal = match expr {
            Expr::Literal(literal) => literal,
            _ => panic!(),
        };
        Self {
            literal,
            parent_node_id,
        }
    }
}

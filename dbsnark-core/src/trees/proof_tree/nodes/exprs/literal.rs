use crate::trees::proof_tree::nodes::{ProverNode, ProverNodeNodeId};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{logical_expr::Expr, scalar::ScalarValue};
use std::sync::Arc;

#[derive(Clone)]
pub struct LiteralExprNode {
    pub node_id: ProverNodeNodeId,
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for LiteralExprNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn node_id(&self) -> ProverNodeNodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn from_expr(
        ctx: &datafusion::prelude::SessionContext,
        expr: Expr,
        parent_logical_plan: datafusion::logical_expr::LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        Self {
            node_id: ProverNodeNodeId::Expr(expr),
        }
    }

    fn append_virtual_witness(
        &self,
        piop_tree: &mut crate::trees::piop_tree::PIOPTree<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }
}

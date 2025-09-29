use crate::trees::proof_tree::nodes::{ProverNode, ProverNodeNodeId};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::logical_expr::Expr;
use std::sync::Arc;

#[derive(Clone)]
pub struct WildcardExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub relative_expr: Expr,
    pub output_expr: Expr,
    pub inputs: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for WildcardExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn node_id(&self) -> ProverNodeNodeId {
        ProverNodeNodeId::Expr(self.relative_expr.clone())
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        self.inputs.iter().collect()
    }
    fn from_expr(
        ctx: &datafusion::prelude::SessionContext,
        expr: Expr,
        parent_logical_plan: datafusion::logical_expr::LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        todo!()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut crate::trees::piop_tree::PIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }
}

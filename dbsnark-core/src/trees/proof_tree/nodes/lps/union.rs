use std::{collections::HashMap, sync::Arc};

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::prelude::SessionContext;

use crate::trees::{piop_tree::PIOPTree, proof_tree::nodes::ProverNode};

pub struct UnionNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub inputs: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for UnionNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        self.inputs.iter().collect()
    }

    fn hint_generation_plans(&self) -> HashMap<String, datafusion::logical_expr::LogicalPlan> {
        todo!()
    }

    fn from_logical_plan(ctx: &SessionContext, plan: datafusion::logical_expr::LogicalPlan) -> Self
    where
        Self: Sized,
    {
        todo!()
    }

    fn node_id(&self) -> crate::trees::proof_tree::nodes::ProverNodeNodeId {
        todo!()
    }

    fn from_expr(
        ctx: &SessionContext,
        expr: datafusion::prelude::Expr,
        parent_logical_plan: datafusion::logical_expr::LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        std::unimplemented!()
    }

    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
    }

    fn name(&self) -> String {
        self.node_id().to_string()
    }

    fn add_virtual_witness(&self, piop_tree: &mut PIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>) {
        todo!()
    }
}

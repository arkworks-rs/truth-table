use std::{collections::HashMap, sync::Arc};

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
};

use crate::prover_trees::{
    piop_tree::PIOPTree,
    proof_tree::nodes::{ProverNode, cost::ProvingCost},
};

pub struct OtherNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub inputs: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
    pub kind: String,
}
impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for OtherNode<F, MvPCS, UvPCS>
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

    fn from_lp(
        ctx: &datafusion::prelude::SessionContext,
        _prover_ctx: arithmetic::ctx::ProverCtx<F, MvPCS, UvPCS>,
        plan: datafusion::logical_expr::LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        todo!()
    }

    fn node_id(&self) -> crate::prover_trees::proof_tree::nodes::ProverNodeNodeId {
        todo!()
    }

    fn from_expr(
        ctx: &datafusion::prelude::SessionContext,
        _prover_ctx: arithmetic::ctx::ProverCtx<F, MvPCS, UvPCS>,
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

    fn cost(
        &self,
        _statistics: datafusion::common::Statistics,
        _schema: datafusion::arrow::datatypes::SchemaRef,
    ) -> ProvingCost {
        todo!()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut PIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }
    fn prove_piop(
        &self,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::prover_trees::piop_tree::PIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        todo!()
    }
}

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{logical_expr as df, prelude::SessionContext};
use std::{collections::HashMap, sync::Arc};

use crate::{ trees::proof_tree::nodes::ProverNode};

pub struct SubqueryAliasNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub alias: String,
    pub input: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
}
impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for SubqueryAliasNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        vec![&self.input]
    }

    fn hint_generation_plans(&self) -> HashMap<String, df::LogicalPlan> {
        todo!()
    }

    fn from_logical_plan(ctx: &SessionContext, plan: df::LogicalPlan) -> Self
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
        parent_logical_plan: df::LogicalPlan,
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

    fn append_virtual_witness(
        &self,
        _arithmetized_tree: &crate::trees::arithmetized_tree::ArithmetizedTree<F, MvPCS, UvPCS>,
        _node_arithmetized_tables: &mut HashMap<
            crate::proof_tree::nodes::ProverNodeNodeId,
            HashMap<String, arithmetic::table::ArithTable<F, MvPCS, UvPCS>>,
        >,
    ) {
        std::todo!()
    }
}

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{
    logical_expr::{self as df, LogicalPlan, LogicalPlanBuilder},
    prelude::SessionContext,
};
use std::{collections::HashMap, sync::Arc};

use crate::trees::proof_tree::nodes::{ProverNode, ProverNodeNodeId};

pub struct LimitNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub skip: Option<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
    pub fetch: Option<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
    pub input: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub node_id: ProverNodeNodeId,
    pub hint_generation_plans: HashMap<String, df::LogicalPlan>,
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for LimitNode<F, MvPCS, UvPCS>
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

    fn node_id(&self) -> ProverNodeNodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(&self) -> HashMap<String, df::LogicalPlan> {
        self.hint_generation_plans.clone()
    }

    fn from_logical_plan(ctx: &SessionContext, plan: LogicalPlan) -> Self
    where
        Self: Sized,
    {
        todo!()
    }

    fn from_expr(
        ctx: &SessionContext,
        expr: datafusion::prelude::Expr,
        parent_logical_plan: LogicalPlan,
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
            ProverNodeNodeId,
            HashMap<String, arithmetic::table::ArithTable<F, MvPCS, UvPCS>>,
        >,
    ) {
        std::todo!()
    }
}

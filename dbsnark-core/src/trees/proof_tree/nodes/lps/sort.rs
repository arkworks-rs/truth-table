use std::{collections::HashMap, sync::Arc};

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{logical_expr as df, prelude::SessionContext};

use crate::{proof_tree::nodes::ProverNodeArc, trees::proof_tree::nodes::ProverNode};

pub struct SortNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub sort_expr: Vec<(ProverNodeArc<F, MvPCS, UvPCS>, bool, bool)>,
    pub fetch: Option<usize>,
    pub input: ProverNodeArc<F, MvPCS, UvPCS>,
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for SortNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&ProverNodeArc<F, MvPCS, UvPCS>> {
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
}

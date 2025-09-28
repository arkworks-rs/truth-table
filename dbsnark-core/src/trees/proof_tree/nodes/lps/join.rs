use std::{collections::HashMap, sync::Arc};

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{
    logical_expr::{self as df, Join},
    prelude::SessionContext,
};

use crate::{proof_tree::nodes::ProverNodeArc, trees::proof_tree::nodes::ProverNode};

pub struct JoinNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub left: ProverNodeArc<F, MvPCS, UvPCS>,
    pub right: ProverNodeArc<F, MvPCS, UvPCS>,
    pub on: Vec<(
        ProverNodeArc<F, MvPCS, UvPCS>,
        ProverNodeArc<F, MvPCS, UvPCS>,
    )>,
    pub filter: Option<ProverNodeArc<F, MvPCS, UvPCS>>,
    pub join_type: df::JoinType,
    pub null_equals_null: bool,
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for JoinNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&ProverNodeArc<F, MvPCS, UvPCS>> {
        vec![&self.left, &self.right]
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

// TODO: Compute the following witnesses:
// pub left_key_support: ArithCol<F, MvPCS, UvPCS>,
// pub right_key_support: ArithCol<F, MvPCS, UvPCS>,
// pub out_key_support: ArithCol<F, MvPCS, UvPCS>,
// pub all_key_support: ArithCol<F, MvPCS, UvPCS>,
// pub join_left_source: ArithCol<F, MvPCS, UvPCS>,
// pub join_right_source: ArithCol<F, MvPCS, UvPCS>,
// pub right_table_multiplicity: TrackedPoly<F, MvPCS, UvPCS>,
// pub left_table_multiplicity: TrackedPoly<F, MvPCS, UvPCS>,

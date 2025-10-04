use std::{collections::HashMap, sync::Arc};

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
};
use datafusion::{
    logical_expr::{self as df, Join},
    prelude::SessionContext,
};

use crate::prover_trees::{
    piop_tree::PIOPTree,
    proof_tree::nodes::{ProverNode, cost::ProvingCost},
};

pub struct JoinNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub left: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub right: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub on: Vec<(
        Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
        Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    )>,
    pub filter: Option<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
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

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        vec![&self.left, &self.right]
    }

    fn hint_generation_plans(&self) -> HashMap<String, df::LogicalPlan> {
        todo!()
    }

    fn from_lp(
        ctx: &SessionContext,
        _prover_ctx: arithmetic::ctx::ProverCtx<F, MvPCS, UvPCS>,
        plan: df::LogicalPlan,
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
        ctx: &SessionContext,
        _prover_ctx: arithmetic::ctx::ProverCtx<F, MvPCS, UvPCS>,
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

// TODO: Compute the following witnesses:
// pub left_key_support: TrackedCol<F, MvPCS, UvPCS>,
// pub right_key_support: TrackedCol<F, MvPCS, UvPCS>,
// pub out_key_support: TrackedCol<F, MvPCS, UvPCS>,
// pub all_key_support: TrackedCol<F, MvPCS, UvPCS>,
// pub join_left_source: TrackedCol<F, MvPCS, UvPCS>,
// pub join_right_source: TrackedCol<F, MvPCS, UvPCS>,
// pub right_table_multiplicity: TrackedPoly<F, MvPCS, UvPCS>,
// pub left_table_multiplicity: TrackedPoly<F, MvPCS, UvPCS>,

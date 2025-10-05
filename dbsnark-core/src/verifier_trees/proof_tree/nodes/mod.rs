//! Verifier-side proof tree nodes and trait definitions.
use std::{any::Any, collections::HashMap, sync::Arc};

use arithmetic::ctx::SharedCtx;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    verifier::Verifier,
};
use datafusion::{
    logical_expr::LogicalPlan,
    prelude::{Expr, SessionContext},
};

use crate::{
    id::NodeId, prover_trees::proof_tree::nodes::ProverNode,
    verifier_trees::piop_tree::VerifierPIOPTree,
};

pub mod exprs;
pub mod lps;

/// Common interface for a verifier proof tree node.
pub trait VerifierNode<F, MvPCS, UvPCS>: Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_expr(
        ctx: &SessionContext,
        _verifier_ctx: SharedCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        parent_logical_plan: LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        unimplemented!()
    }

    fn from_lp(
        ctx: &SessionContext,
        _verifier_ctx: SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        unimplemented!()
    }

    fn as_any(&self) -> &dyn Any;

    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>;

    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
    }

    fn name(&self) -> String {
        self.node_id().to_string()
    }

    fn node_id(&self) -> NodeId;

    fn hint_generation_plans(&self) -> HashMap<String, LogicalPlan> {
        HashMap::new()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
    );

    fn verify_piop(
        &self,
        _verifier: &mut Verifier<F, MvPCS, UvPCS>,
        _piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        todo!()
    }
}

pub fn output_logical_plan<F, MvPCS, UvPCS>(
    node: &Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
) -> Option<LogicalPlan>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    node.hint_generation_plans()
        .into_iter()
        .find_map(|(label, plan)| {
            if label == "output_plan" {
                Some(plan)
            } else {
                None
            }
        })
}

//! Verifier-side proof tree nodes and trait definitions.
pub use super::{exprs, lps};
use crate::{
    proof_nodes::{OUTPUT_PLAN_KEY, id::NodeId},
    verifier::trees::{piop_tree::VerifierPIOPTree, proof_tree::VerifierProofTree},
};
use arithmetic::ctx::SharedCtx;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    verifier::Verifier,
};
use datafusion::{
    arrow::datatypes::SchemaRef,
    logical_expr::LogicalPlan,
    prelude::{Expr, SessionContext},
};
use indexmap::IndexMap;
use std::{any::Any, sync::Arc};
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
        parent_node_id: NodeId,
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
        parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        unimplemented!()
    }
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

    fn hint_generation_plans(
        &self,
        proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, (LogicalPlan, bool)> {
        IndexMap::new()
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
    fn ctx_schema(&self, proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>) -> SchemaRef;
}

impl<F, MvPCS, UvPCS> dyn VerifierNode<F, MvPCS, UvPCS> + '_
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    /// Returns the verifier node as `Any` to support downcasting.
    pub fn as_any(&self) -> &dyn Any {
        self
    }
}

//! Verifier-side proof tree nodes and trait definitions.
pub use super::{exprs, lps};
use crate::{proof_nodes::HintGenerationPlan, tree::NodeId};
use arithmetic::ctx::SharedCtx;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    verifier::ArgVerifier,
};
use datafusion::prelude::DataFrame;
use datafusion::{
    logical_expr::LogicalPlan,
    prelude::{Expr, SessionContext},
};
use indexmap::IndexMap;
use std::{any::Any, sync::Arc};
use tracing::trace;
/// Common interface for a verifier proof tree node.
pub trait VerifierNode<F, MvPCS, UvPCS>: Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>;

    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
    }

    /// Optional human-readable labels for each child edge.
    /// Default implementation leaves every edge unlabeled.
    fn child_edge_labels(&self) -> Vec<Option<String>> {
        self.children().into_iter().map(|_| None).collect()
    }

    fn name(&self) -> String {
        self.node_id().to_string()
    }

    fn node_id(&self) -> NodeId;

    fn hint_generation_plans(&self) -> IndexMap<String, HintGenerationPlan>;

    fn output(&self) -> DataFrame;

    fn is_public(&self) -> bool;

    fn add_virtual_witness(&self, verifier: &mut ArgVerifier<F, MvPCS, UvPCS>);

    fn add_virtual_witness_recursive(&self, verifier: &mut ArgVerifier<F, MvPCS, UvPCS>) {
        trace!(
            "Verifier finished add_virtual_witness_recursive: {}",
            self.name()
        );
    }

    fn verify_piop(
        &self,
        _verifier: &mut ArgVerifier<F, MvPCS, UvPCS>,
    ) -> ark_piop::errors::SnarkResult<()>;

    fn verify_piop_recursive(
        &self,
        verifier: &mut ArgVerifier<F, MvPCS, UvPCS>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
    fn ctx_lp_node(&self) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>>;
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

pub trait VerifierExprNode<F, MvPCS, UvPCS>:
    VerifierNode<F, MvPCS, UvPCS> + Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_expr(
        _ctx: &SessionContext,
        _verifier_ctx: SharedCtx<F, MvPCS, UvPCS>,
        _expr: Expr,
        _parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized;
}

pub trait VerifierLpNode<F, MvPCS, UvPCS>:
    VerifierNode<F, MvPCS, UvPCS> + Any + Send + Sync
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_lp(
        _ctx: &SessionContext,
        _verifier_ctx: SharedCtx<F, MvPCS, UvPCS>,
        _plan: LogicalPlan,
        _parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized;
}

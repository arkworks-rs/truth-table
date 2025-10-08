use crate::{id::NodeId, verifier::nodes::VerifierNode};
use std::{ sync::Arc};

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
};
use datafusion::{
    logical_expr::{self as df, LogicalPlan},
    prelude::SessionContext,
};
use indexmap::IndexMap;
use crate::verifier::trees::piop_tree::VerifierPIOPTree;

/// Proof node representing a base table scan.
///
/// - `plan`: the original DataFusion TableScan logical plan
/// - witness plans include both the relative ("output_plan") plan and the
///   original ("relative_output") scan plan.
pub struct TableScanNode {
    pub plan: LogicalPlan,
    pub node_id: NodeId,
    pub hint_generation_plans: IndexMap<String, LogicalPlan>,
}

impl TableScanNode {
    // Build a relative plan identical to the original scan (no added columns,
    // no padding). Assumes upstream data already contains any required
    // bookkeeping columns (e.g., `activator`).
    pub fn build_output_plan(plan: LogicalPlan) -> df::LogicalPlan {
        plan
    }
}
// TODO: Add the table scan output comitments (the root ones) in the prover
// initial state as a mapping from table names to comitments
impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for TableScanNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_lp(
        ctx: &SessionContext,
        prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        let output_plan = Self::build_output_plan(plan.clone());
        let mut hint_generation_plans = IndexMap::new();

        hint_generation_plans.insert("output_plan".to_string(), output_plan.clone());
        Self {
            plan: plan.clone(),
            node_id: NodeId::LP(plan),
            hint_generation_plans,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(&self) -> IndexMap<String, df::LogicalPlan> {
        self.hint_generation_plans.clone()
    }

    fn from_expr(
        ctx: &SessionContext,
        _verifier_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        expr: datafusion::prelude::Expr,
        parent_logical_plan: LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        std::unimplemented!()
    }

    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
    }
    fn verify_piop(
        &self,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{
    logical_expr::{self as df, LogicalPlan},
    prelude::SessionContext,
};
use std::{collections::HashMap, sync::Arc};

use crate::trees::{
    piop_tree::PIOPTree,
    proof_tree::nodes::{ProverNode, ProverNodeNodeId},
};

/// Proof node representing a base table scan.
///
/// - `plan`: the original DataFusion TableScan logical plan
/// - witness plans include both the relative ("output_plan") plan and the
///   original ("relative_output") scan plan.
pub struct TableScanNode {
    pub plan: LogicalPlan,
    pub node_id: ProverNodeNodeId,
    pub hint_generation_plans: HashMap<String, LogicalPlan>,
}

impl TableScanNode {
    // Build a relative plan identical to the original scan (no added columns,
    // no padding). Assumes upstream data already contains any required
    // bookkeeping columns (e.g., `activator`).
    pub fn build_output_plan(plan: LogicalPlan) -> df::LogicalPlan {
        plan
    }
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for TableScanNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_logical_plan(ctx: &SessionContext, plan: LogicalPlan) -> Self
    where
        Self: Sized,
    {
        let output_plan = Self::build_output_plan(plan.clone());
        let mut hint_generation_plans = HashMap::new();
        hint_generation_plans.insert("output_plan".to_string(), output_plan.clone());
        Self {
            plan: plan.clone(),
            node_id: ProverNodeNodeId::LP(plan),
            hint_generation_plans,
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn node_id(&self) -> ProverNodeNodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(&self) -> HashMap<String, df::LogicalPlan> {
        self.hint_generation_plans.clone()
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

    fn add_virtual_witness(
        &self,
        piop_tree: &mut PIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
    }
}

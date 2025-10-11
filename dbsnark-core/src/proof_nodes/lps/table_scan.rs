// Combined dbsnark-core/src/prover/nodes/lps/table_scan.rs and
// dbsnark-core/src/verifier/nodes/lps/table_scan.rs

use crate::{
    proof_nodes::{cost::ProvingCost, id::NodeId, prover::ProverNode, verifier::VerifierNode, OUTPUT_PLAN_KEY},
    prover::trees::piop_tree::ProverPIOPTree,
    verifier::trees::piop_tree::VerifierPIOPTree,
};
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
use std::sync::Arc;

pub struct ProverTableScanNode {
    pub plan: LogicalPlan,
    pub node_id: NodeId,
    pub hint_generation_plans: IndexMap<String, LogicalPlan>,
}
pub struct VerifierTableScanNode {
    pub plan: LogicalPlan,
    pub node_id: NodeId,
    pub hint_generation_plans: IndexMap<String, LogicalPlan>,
}

// TODO: Add the table scan output comitments (the root ones) in the prover
// initial state as a mapping from table names to comitments
impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for ProverTableScanNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_lp(
        _ctx: &SessionContext,
        _prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        let mut hint_generation_plans = IndexMap::new();

        hint_generation_plans.insert(OUTPUT_PLAN_KEY.to_string(), plan.clone());
        Self {
            plan: plan.clone(),
            node_id: NodeId::LP(plan),
            hint_generation_plans,
        }
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(&self) -> IndexMap<String, df::LogicalPlan> {
        self.hint_generation_plans.clone()
    }

    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
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
        _piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
    }
    fn prove_piop(
        &self,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

// TODO: Add the table scan output comitments (the root ones) in the prover
// initial state as a mapping from table names to comitments
impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for VerifierTableScanNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_lp(
        _ctx: &SessionContext,
        _prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        let mut hint_generation_plans = IndexMap::new();

        hint_generation_plans.insert(OUTPUT_PLAN_KEY.to_string(), plan.clone());
        Self {
            plan: plan.clone(),
            node_id: NodeId::LP(plan),
            hint_generation_plans,
        }
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

    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
    }

    fn add_virtual_witness(
        &self,
        _piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
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

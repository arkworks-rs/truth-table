use crate::{
    proof_nodes::{
        HintGenerationPlan, OUTPUT_PLAN_KEY, cost::ProvingCost, id::NodeId, prover::ProverNode,
        verifier::VerifierNode,
    },
    prover::trees::proof_tree::ProverProofTree,
    verifier::trees::proof_tree::VerifierProofTree,
};
use arithmetic::ACTIVATOR_COL_NAME;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{
    logical_expr::LogicalPlan,
    prelude::SessionContext,
};
use indexmap::IndexMap;
use std::sync::Arc;

pub struct ProverTableScanNode {
    pub plan: LogicalPlan,
    pub node_id: NodeId,
}
pub struct VerifierTableScanNode {
    pub plan: LogicalPlan,
    pub node_id: NodeId,
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
        _parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        debug_assert!(
            plan.schema()
                .field_with_unqualified_name(ACTIVATOR_COL_NAME)
                .is_ok(),
            "table scan plan missing activator column"
        );
        Self {
            plan: plan.clone(),
            node_id: NodeId::LP(plan),
        }
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(
        &self,
        _proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, HintGenerationPlan> {
        let mut hint_generation_plans = IndexMap::new();

        hint_generation_plans.insert(
            OUTPUT_PLAN_KEY.to_string(),
            HintGenerationPlan::new_materialized(OUTPUT_PLAN_KEY.to_string(), self.plan.clone()),
        );
        hint_generation_plans
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

    fn ctx_lp_node(
        &self,
        _proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverNode<F, MvPCS, UvPCS>> {
        todo!()
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
        _parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        debug_assert!(
            plan.schema()
                .field_with_unqualified_name(ACTIVATOR_COL_NAME)
                .is_ok(),
            "table scan plan missing activator column"
        );
        Self {
            plan: plan.clone(),
            node_id: NodeId::LP(plan),
        }
    }

    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(
        &self,
        _proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, HintGenerationPlan> {
        let mut hint_generation_plans = IndexMap::new();

        hint_generation_plans.insert(
            OUTPUT_PLAN_KEY.to_string(),
            HintGenerationPlan::new_materialized(OUTPUT_PLAN_KEY.to_string(), self.plan.clone()),
        );
        hint_generation_plans
    }

    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
    }

    fn ctx_lp_node(
        &self,
        _proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>> {
        todo!()
    }
}

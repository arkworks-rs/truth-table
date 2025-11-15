use crate::{
    proof_nodes::{
        HintGenerationPlan, OUTPUT_PLAN_KEY, cost::ProvingCost, id::NodeId, prover::{ProverLpNode, ProverNode},
        verifier::{VerifierLpNode, VerifierNode},
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
use datafusion::{logical_expr::LogicalPlan, prelude::SessionContext};
use datafusion::prelude::DataFrame;
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

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(
        &self,
        _proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> indexmap::IndexMap<String, DataFrame> {
        todo!()
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

    fn arithmetic_post_process(
        &self,
        _arithmetized_tree: &mut crate::prover::trees::arithmetized_tree::ProverArithmetizedTree<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }

    fn output_data_frame(
        &self,
        _proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> DataFrame {
        todo!()
    }

    fn is_public(&self) -> bool {
        todo!()
    }

    fn add_virtual_witness(
        &self,
        _piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }

    fn prove_piop(
        &self,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> ark_piop::errors::SnarkResult<()> {
        todo!()
    }

}

impl<F, MvPCS, UvPCS> ProverLpNode<F, MvPCS, UvPCS> for ProverTableScanNode
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
}

// TODO: Add the table scan output comitments (the root ones) in the prover
// initial state as a mapping from table names to comitments
impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for VerifierTableScanNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{

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

impl<F, MvPCS, UvPCS> VerifierLpNode<F, MvPCS, UvPCS> for VerifierTableScanNode
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
}


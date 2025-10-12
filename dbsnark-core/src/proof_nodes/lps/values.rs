// Combined dbsnark-core/src/prover/nodes/lps/values.rs and
// dbsnark-core/src/verifier/nodes/lps/values.rs

use crate::{
    proof_nodes::{cost::ProvingCost, id::NodeId, prover::ProverNode, verifier::VerifierNode},
    prover::trees::piop_tree::ProverPIOPTree,
    verifier::trees::piop_tree::VerifierPIOPTree,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
};
use datafusion::prelude::SessionContext;
use indexmap::IndexMap;
use std::sync::Arc;

pub struct ProverValuesNode {}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for ProverValuesNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn hint_generation_plans(&self) -> IndexMap<String, datafusion::logical_expr::LogicalPlan> {
        todo!()
    }

    fn from_lp(
        ctx: &SessionContext,
        _prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: datafusion::logical_expr::LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        todo!()
    }

    fn node_id(&self) -> NodeId {
        todo!()
    }

    fn from_expr(
        ctx: &SessionContext,
        _prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        expr: datafusion::prelude::Expr,
        parent_logical_plan: datafusion::logical_expr::LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        std::unimplemented!()
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
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }
    fn prove_piop(
        &self,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        todo!()
    }
}

pub struct VerifierValuesNode {}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for VerifierValuesNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn hint_generation_plans(&self) -> IndexMap<String, datafusion::logical_expr::LogicalPlan> {
        todo!()
    }

    fn from_lp(
        ctx: &SessionContext,
        _verifier_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: datafusion::logical_expr::LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        todo!()
    }

    fn node_id(&self) -> NodeId {
        todo!()
    }

    fn from_expr(
        ctx: &SessionContext,
        _verifier_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        expr: datafusion::prelude::Expr,
        parent_logical_plan: datafusion::logical_expr::LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        std::unimplemented!()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }
    fn verify_piop(
        &self,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        todo!()
    }
}

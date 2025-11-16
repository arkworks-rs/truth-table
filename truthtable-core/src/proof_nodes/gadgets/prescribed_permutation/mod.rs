use std::marker::PhantomData;
use std::sync::Arc;

use crate::proof_nodes::{id::NodeId, prover::{ProverGadgetNode, ProverNode}, verifier::VerifierNode};
use crate::prover::trees::{piop_tree::ProverPIOPTree, proof_tree::ProverProofTree};
use crate::verifier::trees::{piop_tree::VerifierPIOPTree, proof_tree::VerifierProofTree};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    prover::Prover,
    verifier::Verifier,
};
use datafusion::{
    arrow::datatypes::SchemaRef,
    common::Statistics,
    prelude::DataFrame,
};
use indexmap::IndexMap;

#[derive(Clone)]
pub struct ProverPrescribedPermutationGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    node_id: NodeId,
    _marker: PhantomData<(F, MvPCS, UvPCS)>,
}

impl<F, MvPCS, UvPCS> ProverPrescribedPermutationGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    pub fn new(node_id: NodeId) -> Self {
        Self {
            node_id,
            _marker: PhantomData,
        }
    }
}

impl<F, MvPCS, UvPCS> ProverGadgetNode<F, MvPCS, UvPCS> for ProverPrescribedPermutationGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(
        &self,
        _proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, DataFrame> {
        todo!()
    }

    fn arithmetic_post_process(
        &self,
        _arithmetized_tree: &mut crate::prover::trees::arithmetized_tree::ProverArithmetizedTree<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }



    fn add_virtual_witness(
        &self,
        _piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut Prover<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }

    fn prove_piop(
        &self,
        _prover: &mut Prover<F, MvPCS, UvPCS>,
        _piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        todo!()
    }

    fn cost(&self, _statistics: Statistics, _schema: SchemaRef) -> crate::proof_nodes::cost::ProvingCost {
        todo!()
    }


}



#[derive(Clone)]
pub struct VerifierPrescribedPermutationGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    node_id: NodeId,
    _marker: PhantomData<(F, MvPCS, UvPCS)>,
}

impl<F, MvPCS, UvPCS> VerifierPrescribedPermutationGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    pub fn new(node_id: NodeId) -> Self {
        Self {
            node_id,
            _marker: PhantomData,
        }
    }
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for VerifierPrescribedPermutationGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
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
    ) -> IndexMap<String, DataFrame> {
        todo!()
    }

    fn output_data_frame(
        &self,
        _proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> DataFrame {
        todo!()
    }

    fn is_public(&self) -> bool {
        todo!()
    }

    fn add_virtual_witness(
        &self,
        _piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
        _verifier: &mut Verifier<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }

    fn verify_piop(
        &self,
        _verifier: &mut Verifier<F, MvPCS, UvPCS>,
        _piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        todo!()
    }

    fn ctx_lp_node(
        &self,
        _proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>> {
        todo!()
    }
}

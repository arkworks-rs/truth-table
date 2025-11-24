use std::marker::PhantomData;
use std::sync::Arc;

use crate::proof_nodes::HintDF;
use crate::proof_nodes::prover::ProverGadget;
use crate::proof_nodes::{prover::ProverPlanNode, verifier::VerifierNode};
use crate::tree::NodeId;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
};
use datafusion::{arrow::datatypes::SchemaRef, common::Statistics, prelude::DataFrame};
use indexmap::IndexMap;
#[derive(Clone)]
pub struct Prover<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    node_id: NodeId,
    _marker: PhantomData<(F, MvPCS, UvPCS)>,
}

impl<F, MvPCS, UvPCS> ProverGadget<F, MvPCS, UvPCS> for Prover<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    fn hints(&self, input: &IndexMap<String, HintDF>) -> IndexMap<String, HintDF> {
        todo!()
    }

    fn children(&self) -> Vec<Arc<dyn ProverGadget<F, MvPCS, UvPCS>>> {
        todo!()
    }

    fn name(&self) -> String {
        todo!()
    }
}

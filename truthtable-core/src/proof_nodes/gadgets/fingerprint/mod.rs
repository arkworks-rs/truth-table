use std::marker::PhantomData;
use std::sync::Arc;

use crate::proof_nodes::HintDF;
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

pub const NAME: &str = "Fingerprint_Gadget";
pub const INPUT_DATA_FRAME_KEY: &str = "__fingerprint_input_data_frame__";

#[derive(Clone)]
pub struct ProverFingerprintGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    _marker: PhantomData<(F, MvPCS, UvPCS)>,
}

impl<F, MvPCS, UvPCS> ProverFingerprintGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<F, MvPCS, UvPCS> crate::proof_nodes::prover::ProverGadget<F, MvPCS, UvPCS>
    for ProverFingerprintGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    fn hints(&self, input: &IndexMap<String, HintDF>) -> IndexMap<String, HintDF> {
        input.clone()
    }

    fn children(&self) -> Vec<Arc<dyn crate::proof_nodes::prover::ProverGadget<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn name(&self) -> String {
        NAME.to_string()
    }
}

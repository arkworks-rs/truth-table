use std::marker::PhantomData;
use std::sync::Arc;

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use indexmap::IndexMap;

use crate::nodes::hints::HintDF;

pub const NAME: &str = "Fingerprint_Gadget";
pub const INPUT_DATA_FRAME_KEY: &str = "__fingerprint_input_data_frame__";

#[derive(Clone)]
pub struct Prover<B>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    _marker: PhantomData<(B)>,
}

impl<B> Prover<B>
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

impl<B> crate::nodes::prover::ProverGadget<B>
    for Prover<B>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    fn hints(&self, input: &IndexMap<String, HintDF>) -> IndexMap<String, HintDF> {
        input.clone()
    }

    fn children(&self) -> Vec<Arc<dyn crate::nodes::prover::ProverGadget<B>>> {
        Vec::new()
    }

    fn name(&self) -> String {
        NAME.to_string()
    }
}

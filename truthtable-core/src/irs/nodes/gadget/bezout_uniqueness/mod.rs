use std::sync::Arc;

use crate::nodes::{hints::HintDF, prover::ProverGadget};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
pub const NAME: &str = "Bezout_Uniqueness_Gadget";
pub const INPUT_DATA_FRAME_KEY: &str = "__bezout_uniqueness__input_data_frame__";

#[derive(Clone)]
pub struct Prover<B>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    permutation: Arc<dyn ProverGadget<B>>,
}
impl<B> Prover<B>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    pub fn new() -> Self {
        Self {
            permutation: todo!(),
        }
    }
}

impl<B> ProverGadget<B> for Prover<B>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    fn hints(
        &self,
        input: &indexmap::IndexMap<String, HintDF>,
    ) -> indexmap::IndexMap<String, HintDF> {
        // First get the input data frame
        let input_data_frame = input.get(INPUT_DATA_FRAME_KEY).unwrap();
        // Then see on this input what hints are needed for uniqueness
        self.permutation.hints(input)
    }

    fn children(&self) -> Vec<Arc<dyn ProverGadget<B>>> {
        todo!()
    }

    fn name(&self) -> String {
        NAME.to_string()
    }
}

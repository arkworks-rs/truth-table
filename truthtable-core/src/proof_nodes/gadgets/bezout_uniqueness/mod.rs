use std::marker::PhantomData;
use std::sync::Arc;

use crate::{
    proof_nodes::{HintDF, prover::ProverGadget},
    tree::NodeId,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
pub const NAME: &str = "Bezout_Uniqueness_Gadget";
pub const INPUT_DATA_FRAME_KEY: &str = "__bezout_uniqueness__input_data_frame__";

#[derive(Clone)]
pub struct Prover<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    permutation: Arc<dyn ProverGadget<F, MvPCS, UvPCS>>,
}
impl<F, MvPCS, UvPCS> Prover<F, MvPCS, UvPCS>
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

impl<F, MvPCS, UvPCS> ProverGadget<F, MvPCS, UvPCS> for Prover<F, MvPCS, UvPCS>
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

    fn children(&self) -> Vec<Arc<dyn ProverGadget<F, MvPCS, UvPCS>>> {
        todo!()
    }

    fn name(&self) -> String {
        NAME.to_string()
    }
}

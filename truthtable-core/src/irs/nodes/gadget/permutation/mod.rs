use std::marker::PhantomData;

use crate::nodes::{hints::HintDF, prover::ProverGadget};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};

pub const NAME: &str = "Permutation_Gadget";

#[derive(Clone)]
pub struct ProverPermutationGadget<B>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    _marker: PhantomData<(F, MvPCS, UvPCS)>,
}

impl<B> ProverGadget<B> for ProverPermutationGadget<B>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    fn hints(
        &self,
        input: &indexmap::IndexMap<String, HintDF>,
    ) -> indexmap::IndexMap<String, HintDF> {
        indexmap::IndexMap::new()
    }

    fn children(&self) -> Vec<std::sync::Arc<dyn ProverGadget<B>>> {
        todo!()
    }
    fn name(&self) -> String {
        NAME.to_string()
    }
}

impl<B> ProverPermutationGadget<B>
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

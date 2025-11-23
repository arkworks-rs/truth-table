use std::marker::PhantomData;

use crate::{
    proof_nodes::{HintDF, prover::ProverGadget},
    tree::NodeId,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};

pub const NAME: &str = "Permutation_Gadget";

#[derive(Clone)]
pub struct ProverPermutationGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    _marker: PhantomData<(F, MvPCS, UvPCS)>,
}

impl<F, MvPCS, UvPCS> ProverGadget<F, MvPCS, UvPCS> for ProverPermutationGadget<F, MvPCS, UvPCS>
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

    fn children(&self) -> Vec<std::sync::Arc<dyn ProverGadget<F, MvPCS, UvPCS>>> {
        todo!()
    }
    fn name(&self) -> String {
        NAME.to_string()
    }
}

impl<F, MvPCS, UvPCS> ProverPermutationGadget<F, MvPCS, UvPCS>
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

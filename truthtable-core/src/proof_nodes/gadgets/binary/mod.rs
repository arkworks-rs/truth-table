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
use indexmap::IndexMap;

pub const NAME: &str = "Binary_Gadget";

#[derive(Clone)]
pub struct Prover<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    _marker: PhantomData<(F, MvPCS, UvPCS)>,
}
impl<F, MvPCS, UvPCS> Prover<F, MvPCS, UvPCS>
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

impl<F, MvPCS, UvPCS> ProverGadget<F, MvPCS, UvPCS> for Prover<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    fn hints(&self, input: &IndexMap<String, HintDF>) -> indexmap::IndexMap<String, HintDF> {
        indexmap::IndexMap::new()
    }

    fn children(&self) -> Vec<Arc<dyn ProverGadget<F, MvPCS, UvPCS>>> {
        todo!()
    }
    fn name(&self) -> String {
        NAME.to_string()
    }
}

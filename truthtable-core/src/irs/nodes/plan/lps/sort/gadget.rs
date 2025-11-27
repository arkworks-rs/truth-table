use crate::nodes::hints::HintDF;
use crate::nodes::prover::ProverGadget;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use indexmap::IndexMap;
use std::{marker::PhantomData, sync::Arc};
pub const NAME: &str = "Sort_lp_Gadget";
#[derive(Clone)]
pub struct Prover<B>(PhantomData<(F, MvPCS, UvPCS)>)
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send;

impl<B> Prover<B>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<B> ProverGadget<B> for Prover<B>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn children(&self) -> Vec<Arc<dyn ProverGadget<B>>> {
        vec![]
    }

    fn name(&self) -> String {
        NAME.to_string()
    }

    fn hints(&self, input: &IndexMap<String, HintDF>) -> IndexMap<String, HintDF> {
        let mut hints = IndexMap::new();
        for child in self.children() {
            let child_hints = child.hints(input);
            for (key, hint) in child_hints {
                hints.insert(key, hint);
            }
        }
        hints
    }
}

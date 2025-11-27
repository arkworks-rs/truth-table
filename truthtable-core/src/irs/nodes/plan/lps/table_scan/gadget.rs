use crate::nodes::prover::ProverGadget;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use indexmap::IndexMap;
use std::{marker::PhantomData, sync::Arc};

pub const NAME: &str = "TableScan_lp_Gadget";
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

// impl<B> ProverGadget<B> for Prover<B>
// where
//     F: PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
// {
//     fn children(&self) -> Vec<Arc<dyn ProverGadget<B>>> {
//         Vec::new()
//     }

//     fn name(&self) -> String {
//         NAME.to_string()
//     }

//     fn hints(
//         &self,
//         input: &IndexMap<String, crate::nodes::HintDF>,
//     ) -> IndexMap<String, crate::nodes::HintDF> {
//         IndexMap::new()
//     }
// }

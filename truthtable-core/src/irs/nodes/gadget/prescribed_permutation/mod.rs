use std::marker::PhantomData;
use std::sync::Arc;

use crate::nodes::{hints::HintDF, id::NodeId, prover::ProverGadget};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use indexmap::IndexMap;
#[derive(Clone)]
pub struct Prover<B>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    node_id: NodeId,
    _marker: PhantomData<(B)>,
}

impl<B> ProverGadget<B> for Prover<B>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    fn hints(&self, input: &IndexMap<String, HintDF>) -> IndexMap<String, HintDF> {
        todo!()
    }

    fn children(&self) -> Vec<Arc<dyn ProverGadget<B>>> {
        todo!()
    }

    fn name(&self) -> String {
        todo!()
    }
}

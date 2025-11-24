use crate::{
    proof_nodes::{
        gadgets::{fingerprint::ProverFingerprintGadget, sort},
        prover::ProverGadget,
    },
    tree::NodeId,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use indexmap::IndexMap;
use std::{marker::PhantomData, sync::Arc};

pub const NAME: &str = "TableScan_lp_Gadget";
#[derive(Clone)]
pub struct Prover<F, MvPCS, UvPCS>(PhantomData<(F, MvPCS, UvPCS)>)
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send;

impl<F, MvPCS, UvPCS> Prover<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<F, MvPCS, UvPCS> ProverGadget<F, MvPCS, UvPCS> for Prover<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn children(&self) -> Vec<Arc<dyn ProverGadget<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn name(&self) -> String {
        NAME.to_string()
    }

    fn hints(
        &self,
        input: &IndexMap<String, crate::proof_nodes::HintDF>,
    ) -> IndexMap<String, crate::proof_nodes::HintDF> {
        IndexMap::new()
    }
}

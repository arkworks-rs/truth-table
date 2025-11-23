use crate::{
    proof_nodes::{
        gadgets::{ProverSortGadget, fingerprint::ProverFingerprintGadget},
        prover::ProverGadget,
    },
    tree::NodeId,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use std::sync::Arc;

pub const NAME: &str = "Sort_lp_Gadget";
#[derive(Clone)]
pub struct ProverSortLPGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fingerprint: Arc<ProverFingerprintGadget<F, MvPCS, UvPCS>>,
    sort: Arc<ProverSortGadget<F, MvPCS, UvPCS>>,
}

impl<F, MvPCS, UvPCS> ProverSortLPGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    pub fn new() -> Self {
        let fingerprint = Arc::new(ProverFingerprintGadget::<F, MvPCS, UvPCS>::new());
        let sort = Arc::new(ProverSortGadget::<F, MvPCS, UvPCS>::new());
        Self { fingerprint, sort }
    }
}

impl<F, MvPCS, UvPCS> ProverGadget<F, MvPCS, UvPCS> for ProverSortLPGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn hints(
        &self,
        input: &indexmap::IndexMap<String, crate::proof_nodes::HintDF>,
    ) -> indexmap::IndexMap<String, crate::proof_nodes::HintDF> {
        // This gadget only delegates to its fingerprint child for now.
        self.fingerprint.hints(input)
    }

    fn children(&self) -> Vec<Arc<dyn ProverGadget<F, MvPCS, UvPCS>>> {
        vec![Arc::clone(&self.fingerprint) as Arc<dyn ProverGadget<F, MvPCS, UvPCS>>]
    }

    fn name(&self) -> String {
        NAME.to_string()
    }
}

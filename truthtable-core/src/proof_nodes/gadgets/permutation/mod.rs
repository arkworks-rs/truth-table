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
#[derive(Clone)]
pub struct ProverPermutationGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    node_id: NodeId,
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
    fn node_id(&self) -> NodeId {
        todo!()
    }
}

impl<F, MvPCS, UvPCS> ProverPermutationGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    pub fn new(node_id: NodeId) -> Self {
        Self {
            node_id,
            _marker: PhantomData,
        }
    }
}

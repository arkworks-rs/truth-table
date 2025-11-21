use std::marker::PhantomData;
use std::sync::Arc;

use crate::{
    proof_nodes::{HintDF, prover::ProverGadget},
    tree::{Node, NodeId},
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use indexmap::IndexMap;
#[derive(Clone)]
pub struct ProverBinaryGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    node_id: NodeId,
    _marker: PhantomData<(F, MvPCS, UvPCS)>,
}

impl<F, MvPCS, UvPCS> ProverGadget<F, MvPCS, UvPCS> for ProverBinaryGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    fn hint_dfs(
        &self,
        input: &IndexMap<String, HintDF>,
    ) -> indexmap::IndexMap<String, HintDF> {
        indexmap::IndexMap::new()
    }
}

impl<F, MvPCS, UvPCS> ProverBinaryGadget<F, MvPCS, UvPCS>
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

impl<F, MvPCS, UvPCS> Node<F, MvPCS, UvPCS> for ProverBinaryGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    fn children(&self) -> Vec<Arc<dyn Node<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }
}

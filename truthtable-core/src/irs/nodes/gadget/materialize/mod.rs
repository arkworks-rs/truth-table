use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};

use crate::nodes::id::NodeId;
#[derive(Clone)]
pub struct ProverMaterializeGadget<B>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    node_id: NodeId,
    _marker: PhantomData<(B)>,
}

impl<B> ProverMaterializeGadget<B>
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

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

pub const INPUT_DATA_FRAME_KEY: &str = "__bezout_uniqueness__input_data_frame__";

#[derive(Clone)]
pub struct ProverBezoutUniqunessGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    node_id: NodeId,
    permutation: Arc<dyn ProverGadget<F, MvPCS, UvPCS>>,
}

impl<F, MvPCS, UvPCS> ProverGadget<F, MvPCS, UvPCS> for ProverBezoutUniqunessGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    fn hint_dfs(
        &self,
        input: &indexmap::IndexMap<String, HintDF>,
    ) -> indexmap::IndexMap<String, HintDF> {
        // First get the input data frame
        let input_data_frame = input.get(INPUT_DATA_FRAME_KEY).unwrap();
        // Then see on this input what hints are needed for uniqueness
        self.permutation.hint_dfs(input)
    }

    fn children(&self) -> Vec<Arc<dyn ProverGadget<F, MvPCS, UvPCS>>> {
        todo!()
    }
    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }
}

impl<F, MvPCS, UvPCS> ProverBezoutUniqunessGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    pub fn new(node_id: NodeId) -> Self {
        Self {
            node_id,
            permutation: todo!(),
        }
    }
}

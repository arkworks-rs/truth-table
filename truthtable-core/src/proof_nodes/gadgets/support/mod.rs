use crate::proof_nodes::HintDF;
use crate::proof_nodes::gadgets::{bezout_uniqueness, fingerprint};
use crate::proof_nodes::prover::ProverGadget;
use crate::tree::NodeId;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use indexmap::IndexMap;
use indexmap::indexmap;
use std::sync::Arc;

pub const INPUT_DATA_FRAME_KEY: &str = "__support__input_data_frame__";
pub const SUPPORT_DATA_FRAME_KEY: &str = "__support__support_data_frame__";

#[derive(Clone)]
pub struct Prover<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    node_id: NodeId,
    nodup: Arc<dyn ProverGadget<F, MvPCS, UvPCS>>,
    support_fingerprint: Arc<dyn ProverGadget<F, MvPCS, UvPCS>>,
    input_fingerprint: Arc<dyn ProverGadget<F, MvPCS, UvPCS>>,
}

impl<F, MvPCS, UvPCS> ProverGadget<F, MvPCS, UvPCS> for Prover<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    fn node_id(&self) -> NodeId {
        todo!()
    }
    fn hint_dfs(&self, input: &IndexMap<String, HintDF>) -> IndexMap<String, HintDF> {
        // First get the inputs
        let input_data_frame = input.get(INPUT_DATA_FRAME_KEY).unwrap();
        let support_data_frame = input.get(SUPPORT_DATA_FRAME_KEY).unwrap();
        // Then see on this input what hints are needed for uniqueness
        let uniqueness_input = indexmap! {
            bezout_uniqueness::INPUT_DATA_FRAME_KEY.to_string() => support_data_frame.clone(),
        };
        let uniqueness_hints = self.nodup.hint_dfs(&uniqueness_input);
        // Then see on this input what hints are needed for support fingerprint
        let input_fingerprint_input = indexmap! {
            fingerprint::INPUT_DATA_FRAME_KEY.to_string() => input_data_frame.clone(),
        };
        let input_fingerprint_hints = self.input_fingerprint.hint_dfs(&input_fingerprint_input);
        // Then see on this input what hints are needed for support fingerprint
        let support_fingerprint_input = indexmap! {
            fingerprint::INPUT_DATA_FRAME_KEY.to_string() => support_data_frame.clone(),
        };
        let support_fingerprint_hints = self
            .support_fingerprint
            .hint_dfs(&support_fingerprint_input);
        // Combine all hints
        let mut all_hints = IndexMap::new();
        all_hints.extend(uniqueness_hints);
        all_hints.extend(input_fingerprint_hints);
        all_hints.extend(support_fingerprint_hints);
        //TODO: Trace here
        all_hints
    }

    fn children(&self) -> Vec<Arc<dyn ProverGadget<F, MvPCS, UvPCS>>> {
        todo!()
    }
}

impl<F, MvPCS, UvPCS> Prover<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    pub fn new(node_id: NodeId) -> Self {
        Self {
            node_id,
            nodup: todo!(),
            support_fingerprint: todo!(),
            input_fingerprint: todo!(),
        }
    }
}

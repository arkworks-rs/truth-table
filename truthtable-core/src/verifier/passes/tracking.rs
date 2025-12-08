use ark_piop::{SnarkBackend, verifier::ArgVerifier};

use crate::{
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
        payloads::HintDFPayload,
    },
    verifier::payloads::TrackedPayload,
};
use std::cell::RefCell;

/// A tracking pass that tracks and commits the verifier's arithmetized tables
///
/// This pass converts an IR with arithmetized tables into an IR with tracked tables; i.e. tables that are commited and added to the transcript, therefore tracked by the SNARK verifier with an associated id. Note that this pass is stateful, as it requires access to the verifier instance to perform the tracking and committing.
pub struct TrackingPass<B: SnarkBackend> {
    verifier: RefCell<ArgVerifier<B>>,
}

impl<B: SnarkBackend> TrackingPass<B> {
    pub fn new(verifier: ArgVerifier<B>) -> Self {
        Self {
            verifier: RefCell::new(verifier),
        }
    }
}

impl<B> LocalPass<B, HintDFPayload, TrackedPayload<B>> for TrackingPass<B>
where
    B: SnarkBackend,
{
    fn transform(
        &self,
        _node: &Node<B>,
        _id: NodeId,
        payload: Option<&HintDFPayload>,
    ) -> Option<TrackedPayload<B>> {
        match payload? {
            HintDFPayload::PlanPayload(hint_df) => Some(TrackedPayload::PlanPayload(todo!())),
            HintDFPayload::GadgetPayload(map) => {
                todo!()
            }
        }
    }
}

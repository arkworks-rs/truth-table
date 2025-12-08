use arithmetic::table_oracle::TrackedTableOracle;
use ark_piop::{SnarkBackend, verifier::ArgVerifier};
use datafusion::arrow::datatypes::Schema;
use datafusion_common::DFSchema;
use indexmap::IndexMap;

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
            HintDFPayload::PlanPayload(hint_df) => Some(TrackedPayload::PlanPayload(
                track_hint_df(hint_df, &self.verifier),
            )),
            HintDFPayload::GadgetPayload(map) => {
                let mut out = indexmap::IndexMap::new();
                for (k, hint_df) in map {
                    out.insert(k.clone(), track_hint_df(hint_df, &self.verifier));
                }
                Some(TrackedPayload::GadgetPayload(out))
            }
        }
    }
}

fn track_hint_df<B: SnarkBackend>(
    hint_df: &crate::irs::nodes::hints::HintDF,
    verifier: &RefCell<ArgVerifier<B>>,
) -> TrackedTableOracle<B> {
    let arrow_schema: Schema =
        <DFSchema as AsRef<Schema>>::as_ref(hint_df.data_frame().schema()).clone();
    let mut tracked_oracles: IndexMap<_, _> = IndexMap::new();
    let mut log_size = 0usize;

    let mut verifier = verifier.borrow_mut();
    for (field, should_mat) in hint_df.field_materialization_iter() {
        if !*should_mat {
            continue;
        }
        // Use the next expected id so the verifier's tracker stays in sync with the proof
        let id = verifier.peek_next_id();
        let oracle = verifier
            .track_mv_com_by_id(id)
            .expect("verifier should track prover commitment by id");
        if log_size == 0 {
            log_size = oracle.log_size();
        } else {
            debug_assert_eq!(log_size, oracle.log_size());
        }
        tracked_oracles.insert(field.clone(), oracle);
    }

    TrackedTableOracle::new(Some(arrow_schema), tracked_oracles, log_size)
}

use arithmetic::table_oracle::TrackedTableOracle;
use ark_piop::{SnarkBackend, verifier::ArgVerifier};
use datafusion::arrow::datatypes::{FieldRef, Schema};
use datafusion_common::DFSchema;
use indexmap::IndexMap;

use crate::irs::nodes::IsNode;
use crate::{
    ctx_oracles::CtxOracles,
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
        payloads::HintDFPayload,
    },
    verifier::payloads::TrackedPayload,
};
use std::cell::RefCell;
use std::sync::Arc;

const QUALIFIER_METADATA_KEY: &str = "tt.qualifier";
/// A tracking pass that tracks and commits the verifier's arithmetized tables
///
/// This pass converts an IR with arithmetized tables into an IR with tracked tables; i.e. tables that are commited and added to the transcript, therefore tracked by the SNARK verifier with an associated id. Note that this pass is stateful, as it requires access to the verifier instance to perform the tracking and committing.
pub struct TrackingPass<B: SnarkBackend> {
    verifier: RefCell<ArgVerifier<B>>,
    ctx_oracles: CtxOracles<B>,
}

impl<B: SnarkBackend> TrackingPass<B> {
    pub fn new(verifier: ArgVerifier<B>, ctx_oracles: CtxOracles<B>) -> Self {
        Self {
            verifier: RefCell::new(verifier),
            ctx_oracles,
        }
    }
}

impl<B> LocalPass<B, HintDFPayload, TrackedPayload<B>> for TrackingPass<B>
where
    B: SnarkBackend,
{
    fn order(&self) -> crate::irs::ir::PassOrder {
        crate::irs::ir::PassOrder::PostOrder
    }
    fn transform(
        &self,
        _node: &Node<B>,
        _id: NodeId,
        payload: Option<&HintDFPayload>,
    ) -> Option<TrackedPayload<B>> {
        // If there is no payload, do nothing
        let payload = payload?;
        match payload {
            // If the payload is a plan,
            HintDFPayload::PlanPayload(hint_df) => {
                // TableScan commitments must come from the proof so the verifier follows the
                // exact IDs and domains chosen by the prover for this run.
                track_hint_df(hint_df, &self.verifier).map(TrackedPayload::PlanPayload)
            }
            HintDFPayload::GadgetPayload(map) => {
                let mut out = IndexMap::new();
                for (key, hint_df) in map.iter() {
                    if let Some(table) = track_hint_df(hint_df, &self.verifier) {
                        out.insert(key.clone(), table);
                    }
                }
                if out.is_empty() {
                    None
                } else {
                    Some(TrackedPayload::GadgetPayload(out))
                }
            }
        }
    }

    fn name(&self) -> &'static str {
        "Verifier Tracking"
    }
}

fn track_hint_df<B: SnarkBackend>(
    hint_df: &crate::irs::nodes::hints::HintDF,
    verifier: &RefCell<ArgVerifier<B>>,
) -> Option<TrackedTableOracle<B>> {
    let df_schema_ref = hint_df.data_frame().schema();
    let base_schema: Schema = <DFSchema as AsRef<Schema>>::as_ref(df_schema_ref).clone();
    let qualified_fields = qualify_fields(&df_schema_ref);
    // Initialize some variables
    let mut tracked_oracles: IndexMap<_, _> = IndexMap::new();
    let mut log_size = 0usize;

    let mut verifier = verifier.borrow_mut();
    // Iterate through each field that needs materialization
    for (field, should_mat) in hint_df.field_materialization_iter() {
        if !*should_mat {
            continue;
        }
        let qualified_field = qualified_fields
            .get(field)
            .cloned()
            .unwrap_or_else(|| field.clone());
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
        tracked_oracles.insert(qualified_field, oracle);
    }
    // If there was no columns to be materialized, return None
    if tracked_oracles.is_empty() {
        None
    } else {
        let schema = Some(build_tracked_schema(
            &base_schema,
            tracked_oracles.keys(),
            None,
        ));
        Some(TrackedTableOracle::new(schema, tracked_oracles, log_size))
    }
}

fn build_tracked_schema<'a>(
    base_schema: &Schema,
    tracked_fields: impl Iterator<Item = &'a FieldRef>,
    oracle_schema: Option<&Schema>,
) -> Schema {
    // Keep field ordering exactly aligned with tracked_oracles keys, while
    // merging table-level metadata from hint-df + oracle schema.
    let mut metadata = base_schema.metadata().clone();
    if let Some(schema) = oracle_schema {
        metadata.extend(schema.metadata().clone());
    }
    let fields = tracked_fields
        .map(|f| f.as_ref().clone())
        .collect::<Vec<_>>();
    Schema::new_with_metadata(fields, metadata)
}

fn qualify_fields(df_schema: &DFSchema) -> IndexMap<FieldRef, FieldRef> {
    let mut out = IndexMap::new();
    for (qualifier, field) in df_schema.iter() {
        let mut updated = field.as_ref().clone();
        if updated.name() == arithmetic::ACTIVATOR_COL_NAME
            || updated.name() == arithmetic::ROW_ID_COL_NAME
        {
            out.insert(field.clone(), Arc::new(updated));
            continue;
        }
        if let Some(qualifier) = qualifier {
            // Mirror prover-side qualifier metadata to keep schemas aligned.
            let mut metadata = updated.metadata().clone();
            metadata.insert(QUALIFIER_METADATA_KEY.to_string(), qualifier.to_string());
            updated = updated.with_metadata(metadata);
        }
        out.insert(field.clone(), Arc::new(updated));
    }
    out
}

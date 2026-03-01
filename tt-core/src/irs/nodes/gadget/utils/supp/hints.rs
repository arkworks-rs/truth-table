use ark_piop::SnarkBackend;
use indexmap::IndexMap;

use crate::irs::shared_ir::OutputPlannedIr;
use crate::irs::{
    nodes::{NodeId, hints::HintDF},
    payloads::PayloadStructure,
};

use super::{ORIG_LABEL, SUPER_LABEL};

pub(super) fn io_plans<B: SnarkBackend>(
    planned_ir: &OutputPlannedIr<B>,
    id: NodeId,
) -> (HintDF, HintDF) {
    let supp_payload = match planned_ir.payload_for_node(&id) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => panic!("No support payload found for node {:?}", id),
    };
    let orig_hint = supp_payload
        .get(ORIG_LABEL)
        .expect("Original hint not found")
        .clone();
    let support_hint = supp_payload
        .get(SUPER_LABEL)
        .expect("Support hint not found")
        .clone();
    (orig_hint, support_hint)
}

pub(super) fn populate_nodup<B: SnarkBackend>(
    planned_ir: &mut OutputPlannedIr<B>,
    nodup_id: NodeId,
    support_hint: HintDF,
) {
    let mut nodup_payload = match planned_ir.payload_for_node(&nodup_id) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };

    nodup_payload.insert(
        crate::irs::nodes::gadget::utils::nodup::INPUT_LABEL.to_string(),
        support_hint,
    );

    planned_ir.set_payload_for_node(
        nodup_id,
        Some(PayloadStructure::GadgetPayload(nodup_payload)),
    );
}

pub(super) fn populate_lookup<B: SnarkBackend>(
    planned_ir: &mut OutputPlannedIr<B>,
    lookup_id: NodeId,
    orig_hint: HintDF,
    support_hint: HintDF,
) {
    let mut lookup_payload = match planned_ir.payload_for_node(&lookup_id) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };

    lookup_payload.insert(
        crate::irs::nodes::gadget::utils::lookup::INCLUDED_LABEL.to_string(),
        orig_hint,
    );
    lookup_payload.insert(
        crate::irs::nodes::gadget::utils::lookup::SUPER_LABEL.to_string(),
        support_hint,
    );

    planned_ir.set_payload_for_node(
        lookup_id,
        Some(PayloadStructure::GadgetPayload(lookup_payload)),
    );
}

use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_FIELD, is_system_column, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_piop::{SnarkBackend, prover::ArgProver, verifier::ArgVerifier};
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use indexmap::IndexMap;

use crate::irs::{nodes::NodeId, payloads::PayloadStructure};

use super::{ORIG_LABEL, ORIG_RLC_LABEL, SUPER_LABEL, SUPER_RLC_LABEL};

pub(super) fn io_tables_prover<B: SnarkBackend>(
    virtualized_ir: &crate::prover::irs::VirtualizedIr<B>,
    id: NodeId,
) -> (
    IndexMap<String, TrackedTable<B>>,
    TrackedTable<B>,
    TrackedTable<B>,
) {
    let Some(PayloadStructure::GadgetPayload(payload)) =
        virtualized_ir.payload_for_node(&id).cloned()
    else {
        panic!("Expected gadget payload for Supp gadget node");
    };

    let Some(orig_table) = payload.get(ORIG_LABEL).cloned() else {
        panic!("Expected original table for Supp gadget");
    };
    let Some(super_table) = payload.get(SUPER_LABEL).cloned() else {
        panic!("Expected support table for Supp gadget");
    };

    (payload, orig_table, super_table)
}

pub(super) fn io_tables_verifier<B: SnarkBackend>(
    virtualized_ir: &crate::verifier::irs::VirtualizedIr<B>,
    id: NodeId,
) -> (
    IndexMap<String, TrackedTableOracle<B>>,
    TrackedTableOracle<B>,
    TrackedTableOracle<B>,
) {
    let Some(PayloadStructure::GadgetPayload(payload)) =
        virtualized_ir.payload_for_node(&id).cloned()
    else {
        panic!("Expected gadget payload for Supp gadget node");
    };

    let Some(orig_table) = payload.get(ORIG_LABEL).cloned() else {
        panic!("Expected original table for Supp gadget");
    };
    let Some(super_table) = payload.get(SUPER_LABEL).cloned() else {
        panic!("Expected support table for Supp gadget");
    };

    (payload, orig_table, super_table)
}

pub(super) fn populate_self_rlc_payload_prover<B: SnarkBackend>(
    id: NodeId,
    virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    payload: IndexMap<String, TrackedTable<B>>,
    orig_rlc: TrackedTable<B>,
    super_rlc: TrackedTable<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let mut updated_payload = payload;
    updated_payload.insert(ORIG_RLC_LABEL.to_string(), orig_rlc);
    updated_payload.insert(SUPER_RLC_LABEL.to_string(), super_rlc);
    virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(updated_payload)));
    Ok(())
}

pub(super) fn populate_nodup_payload_prover<B: SnarkBackend>(
    virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    nodup_id: NodeId,
    super_table: TrackedTable<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let mut nodup_payload = match virtualized_ir.payload_for_node(&nodup_id) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    nodup_payload.insert(
        crate::irs::nodes::gadget::utils::nodup::INPUT_LABEL.to_string(),
        super_table,
    );
    virtualized_ir.set_payload_for_node(
        nodup_id,
        Some(PayloadStructure::GadgetPayload(nodup_payload)),
    );
    Ok(())
}

pub(super) fn populate_lookup_payload_prover<B: SnarkBackend>(
    virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    lookup_id: NodeId,
    orig_rlc: TrackedTable<B>,
    super_rlc: TrackedTable<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let mut lookup_payload = match virtualized_ir.payload_for_node(&lookup_id) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    lookup_payload.insert(
        crate::irs::nodes::gadget::utils::lookup::INCLUDED_LABEL.to_string(),
        orig_rlc,
    );
    lookup_payload.insert(
        crate::irs::nodes::gadget::utils::lookup::SUPER_LABEL.to_string(),
        super_rlc,
    );
    virtualized_ir.set_payload_for_node(
        lookup_id,
        Some(PayloadStructure::GadgetPayload(lookup_payload)),
    );
    Ok(())
}

pub(super) fn populate_self_rlc_payload_verifier<B: SnarkBackend>(
    id: NodeId,
    virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    payload: IndexMap<String, TrackedTableOracle<B>>,
    orig_rlc: TrackedTableOracle<B>,
    super_rlc: TrackedTableOracle<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let mut updated_payload = payload;
    updated_payload.insert(ORIG_RLC_LABEL.to_string(), orig_rlc);
    updated_payload.insert(SUPER_RLC_LABEL.to_string(), super_rlc);
    virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(updated_payload)));
    Ok(())
}

pub(super) fn populate_nodup_payload_verifier<B: SnarkBackend>(
    virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    nodup_id: NodeId,
    super_table: TrackedTableOracle<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let mut nodup_payload = match virtualized_ir.payload_for_node(&nodup_id) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    nodup_payload.insert(
        crate::irs::nodes::gadget::utils::nodup::INPUT_LABEL.to_string(),
        super_table,
    );
    virtualized_ir.set_payload_for_node(
        nodup_id,
        Some(PayloadStructure::GadgetPayload(nodup_payload)),
    );
    Ok(())
}

pub(super) fn populate_lookup_payload_verifier<B: SnarkBackend>(
    virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    lookup_id: NodeId,
    orig_rlc: TrackedTableOracle<B>,
    super_rlc: TrackedTableOracle<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let mut lookup_payload = match virtualized_ir.payload_for_node(&lookup_id) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    lookup_payload.insert(
        crate::irs::nodes::gadget::utils::lookup::INCLUDED_LABEL.to_string(),
        orig_rlc,
    );
    lookup_payload.insert(
        crate::irs::nodes::gadget::utils::lookup::SUPER_LABEL.to_string(),
        super_rlc,
    );
    virtualized_ir.set_payload_for_node(
        lookup_id,
        Some(PayloadStructure::GadgetPayload(lookup_payload)),
    );
    Ok(())
}

pub(super) fn folding_challenges_from_table<B: SnarkBackend>(table: &TrackedTable<B>) -> Vec<B::F> {
    let num_data = table.num_data_tracked_cols();
    if num_data == 0 {
        return Vec::new();
    }
    let (_, first_poly) = table
        .tracked_polys_iter()
        .next()
        .expect("supp folding requires at least one tracked column");
    let mut prover = ArgProver::new_from_tracker_rc(first_poly.tracker());
    // Use Fiat-Shamir challenges so folded columns are collision-resistant.
    (0..num_data)
        .map(|_| {
            prover
                .get_and_append_challenge(b"supp_fold")
                .expect("supp folding challenge should succeed")
        })
        .collect()
}

pub(super) fn io_rlc_prover<B: SnarkBackend>(
    orig_table: &TrackedTable<B>,
    super_table: &TrackedTable<B>,
) -> (TrackedTable<B>, TrackedTable<B>) {
    let folding_challs = folding_challenges_from_table(orig_table);
    let orig_rlc =
        fold_table_to_single_col_with_challs(orig_table, ORIG_RLC_LABEL, &folding_challs);
    let super_rlc =
        fold_table_to_single_col_with_challs(super_table, SUPER_RLC_LABEL, &folding_challs);
    (orig_rlc, super_rlc)
}

pub(super) fn folding_challenges_from_table_oracle<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
) -> Vec<B::F> {
    let num_data = table.num_data_tracked_col_oracles();
    if num_data == 0 {
        return Vec::new();
    }
    let (_, first_oracle) = table
        .tracked_oracles_iter()
        .next()
        .expect("supp folding requires at least one tracked oracle");
    let mut verifier = ArgVerifier::new_from_tracker_rc(first_oracle.tracker());
    // Mirror prover-side Fiat-Shamir challenges.
    (0..num_data)
        .map(|_| {
            verifier
                .get_and_append_challenge(b"supp_fold")
                .expect("supp folding challenge should succeed")
        })
        .collect()
}

pub(super) fn io_rlc_verifier<B: SnarkBackend>(
    orig_table: &TrackedTableOracle<B>,
    super_table: &TrackedTableOracle<B>,
) -> (TrackedTableOracle<B>, TrackedTableOracle<B>) {
    let folding_challs = folding_challenges_from_table_oracle(orig_table);
    let orig_rlc =
        fold_table_oracle_to_single_col_with_challs(orig_table, ORIG_RLC_LABEL, &folding_challs);
    let super_rlc =
        fold_table_oracle_to_single_col_with_challs(super_table, SUPER_RLC_LABEL, &folding_challs);
    (orig_rlc, super_rlc)
}

fn folded_field_from_schema(schema: Option<&Schema>, label: &str) -> FieldRef {
    if let Some(schema) = schema
        && let Some(field) = schema.fields().iter().find(|f| !is_system_column(f.name()))
    {
        return Arc::new(Field::new(
            label,
            field.data_type().clone(),
            field.is_nullable(),
        ));
    }
    Arc::new(Field::new(label, DataType::UInt64, false))
}

pub(super) fn fold_table_to_single_col_with_challs<B: SnarkBackend>(
    table: &TrackedTable<B>,
    label: &str,
    challenges: &[B::F],
) -> TrackedTable<B> {
    let num_data = table.num_data_tracked_cols();
    assert_eq!(
        num_data,
        challenges.len(),
        "supp folding challenges must align with data columns"
    );
    let folded_col = table.fold_all_data_columns(challenges);

    let data_field = folded_field_from_schema(table.schema_ref(), label);
    let mut fields = vec![data_field.as_ref().clone()];
    let mut tracked_polys = IndexMap::new();
    tracked_polys.insert(data_field, folded_col.data_tracked_poly());

    if let Some(activator) = table.activator_tracked_poly() {
        fields.push(ACTIVATOR_FIELD.as_ref().clone());
        tracked_polys.insert(ACTIVATOR_FIELD.clone(), activator);
    }

    TrackedTable::new(Some(Schema::new(fields)), tracked_polys, table.log_size())
}

pub(super) fn fold_table_oracle_to_single_col_with_challs<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    label: &str,
    challenges: &[B::F],
) -> TrackedTableOracle<B> {
    let num_data = table.num_data_tracked_col_oracles();
    assert_eq!(
        num_data,
        challenges.len(),
        "supp folding challenges must align with data columns"
    );
    let folded_col = table.fold_all_data_oracles(challenges);

    let data_field = folded_field_from_schema(table.schema_ref(), label);
    let mut fields = vec![data_field.as_ref().clone()];
    let mut tracked_oracles = IndexMap::new();
    tracked_oracles.insert(data_field, folded_col.data_tracked_oracle());

    if let Some(activator) = table.activator_tracked_poly() {
        fields.push(ACTIVATOR_FIELD.as_ref().clone());
        tracked_oracles.insert(ACTIVATOR_FIELD.clone(), activator);
    }

    TrackedTableOracle::new(Some(Schema::new(fields)), tracked_oracles, table.log_size())
}

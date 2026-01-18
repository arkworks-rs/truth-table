use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_FIELD, is_system_column, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_piop::{SnarkBackend, piop::PIOP, prover::ArgProver, verifier::ArgVerifier};
use col_toolbox::bezout_based_multi_col_supp_check::{
    BezoutMultiColSuppCheckPIOP, BezoutMultiColSuppCheckProverInput,
    BezoutMultiColSuppCheckVerifierInput,
};
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};
mod hints;
#[cfg(test)]
mod tests;

pub const ORIG_LABEL: &str = "__orig__";
pub const ORIG_RLC_LABEL: &str = "__orig-rlc__";
pub const SUPER_LABEL: &str = "__super__";
pub const SUPER_RLC_LABEL: &str = "__super-rlc__";

pub struct GadgetNode<B: SnarkBackend> {
    lookup: Arc<Node<B>>,
    nodup: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Support".to_string()
    }

    fn display(&self) -> String {
        self.name()
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let supp_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        let orig_hint = match supp_payload.get(ORIG_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };
        let support_hint = match supp_payload.get(SUPER_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };

        //////////////////////////////
        let mut nodup_payload = match planned_ir.payload_for_node(&self.nodup.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };

        nodup_payload.insert(
            crate::irs::nodes::gadget::utils::nodup::INPUT_LABEL.to_string(),
            support_hint.clone(),
        );

        planned_ir.set_payload_for_node(
            self.nodup.id(),
            Some(PayloadStructure::GadgetPayload(nodup_payload)),
        );

        let mut lookup_payload = match planned_ir.payload_for_node(&self.lookup.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };

        lookup_payload.insert(
            crate::irs::nodes::gadget::utils::lookup::INCLUDED_LABEL.to_string(),
            orig_hint.clone(),
        );
        lookup_payload.insert(
            crate::irs::nodes::gadget::utils::lookup::SUPER_LABEL.to_string(),
            support_hint,
        );

        planned_ir.set_payload_for_node(
            self.lookup.id(),
            Some(PayloadStructure::GadgetPayload(lookup_payload)),
        );
        Ok(())
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        vec![self.lookup.clone(), self.nodup.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
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
        /////////////////////////

        let folding_challs = folding_challenges_from_table(&orig_table);
        let orig_rlc =
            fold_table_to_single_col_with_challs(&orig_table, ORIG_RLC_LABEL, &folding_challs);
        let super_rlc =
            fold_table_to_single_col_with_challs(&super_table, SUPER_RLC_LABEL, &folding_challs);

        populate_self_rlc_payload_prover(
            id,
            virtualized_ir,
            payload,
            orig_rlc.clone(),
            super_rlc.clone(),
        )?;
        populate_nodup_payload_prover(virtualized_ir, self.nodup.id(), super_table.clone())?;
        populate_lookup_payload_prover(
            virtualized_ir,
            self.lookup.id(),
            orig_rlc.clone(),
            super_rlc,
        )?;
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
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

        //////////////////////////
        let folding_challs = folding_challenges_from_table_oracle(&orig_table);
        let orig_rlc = fold_table_oracle_to_single_col_with_challs(
            &orig_table,
            ORIG_RLC_LABEL,
            &folding_challs,
        );
        let super_rlc = fold_table_oracle_to_single_col_with_challs(
            &super_table,
            SUPER_RLC_LABEL,
            &folding_challs,
        );

        populate_self_rlc_payload_verifier(
            id,
            virtualized_ir,
            payload,
            orig_rlc.clone(),
            super_rlc.clone(),
        )?;
        populate_nodup_payload_verifier(virtualized_ir, self.nodup.id(), super_table.clone())?;
        populate_lookup_payload_verifier(
            virtualized_ir,
            self.lookup.id(),
            orig_rlc.clone(),
            super_rlc,
        )?;

        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for Supp gadget node");
        };

        let Some(orig_table) = payload.get(ORIG_LABEL).cloned() else {
            panic!("Expected original table for Supp gadget");
        };
        let Some(supp_table) = payload.get(SUPER_LABEL).cloned() else {
            panic!("Expected support table for Supp gadget");
        };

        let input = BezoutMultiColSuppCheckProverInput {
            orig_tracked_table: orig_table,
            supp_tracked_table: supp_table,
        };
        BezoutMultiColSuppCheckPIOP::<B>::prove(prover, input)?;
        Ok(())
    }

    fn verify(
        &self,
        verifier: &mut ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for Supp gadget node");
        };

        let Some(orig_table) = payload.get(ORIG_LABEL).cloned() else {
            panic!("Expected original table for Supp gadget");
        };
        let Some(supp_table) = payload.get(SUPER_LABEL).cloned() else {
            panic!("Expected support table for Supp gadget");
        };

        let input = BezoutMultiColSuppCheckVerifierInput {
            orig_tracked_table_oracle: orig_table,
            supp_tracked_table_oracle: supp_table,
        };
        BezoutMultiColSuppCheckPIOP::<B>::verify(verifier, input)?;
        Ok(())
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn honest_prover_check(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> Default for GadgetNode<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new() -> Self {
        let lookup = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::lookup::GadgetNode::new(),
        )));
        let nodup = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::nodup::GadgetNode::new(),
        )));
        Self { lookup, nodup }
    }
}

fn folding_challenges_from_table<B: SnarkBackend>(table: &TrackedTable<B>) -> Vec<B::F> {
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

fn folding_challenges_from_table_oracle<B: SnarkBackend>(
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

fn populate_self_rlc_payload_prover<B: SnarkBackend>(
    id: crate::irs::nodes::NodeId,
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

fn populate_nodup_payload_prover<B: SnarkBackend>(
    virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    nodup_id: crate::irs::nodes::NodeId,
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

fn populate_lookup_payload_prover<B: SnarkBackend>(
    virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    lookup_id: crate::irs::nodes::NodeId,
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

fn populate_self_rlc_payload_verifier<B: SnarkBackend>(
    id: crate::irs::nodes::NodeId,
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

fn populate_nodup_payload_verifier<B: SnarkBackend>(
    virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    nodup_id: crate::irs::nodes::NodeId,
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

fn populate_lookup_payload_verifier<B: SnarkBackend>(
    virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    lookup_id: crate::irs::nodes::NodeId,
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

fn fold_table_to_single_col_with_challs<B: SnarkBackend>(
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

fn fold_table_oracle_to_single_col_with_challs<B: SnarkBackend>(
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

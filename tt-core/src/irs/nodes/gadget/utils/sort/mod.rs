use std::sync::Arc;

use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_piop::SnarkBackend;
use ark_piop::{
    prover::structs::polynomial::TrackedPoly, verifier::structs::oracle::TrackedOracle,
};
use datafusion::arrow::datatypes::{DataType, Field};
use either::Either;
use indexmap::IndexMap;

use crate::irs::nodes::gadget::utils::prescr_perm;
use crate::{
    irs::{
        nodes::{
            IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps,
            gadget::utils::sort::hints::{populate_rotated, populate_tie_indicator},
        },
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};
mod hints;
#[cfg(test)]
mod tests;
pub const TABLE_LABEL: &str = "__input__";
pub const ROTATED_INPUT_LABEL: &str = "__rotated_input__";
pub const TIE_INDICATOR_LABEL: &str = "__tie_indicator__";
pub struct GadgetNode<B: SnarkBackend> {
    prescr_perm: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Sort".to_string()
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
        let mut gadget_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        let input_hint = match gadget_payload.get(TABLE_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };

        populate_rotated(&mut gadget_payload, &input_hint);
        populate_tie_indicator(&mut gadget_payload, &input_hint);
        // Strip row-id before storing to avoid exposing it in gadget payloads.
        let sanitized_input = crate::irs::nodes::hints::strip_row_id_from_hint(&input_hint);
        gadget_payload.insert(TABLE_LABEL.to_string(), sanitized_input);
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));
        Ok(())
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.prescr_perm.clone()]
    }
}

fn build_perm_table_prover<B: SnarkBackend>(left: &TrackedTable<B>) -> TrackedTable<B> {
    let data_idx = left
        .data_tracked_polys_indices()
        .first()
        .copied()
        .unwrap_or_else(|| panic!("Sort permutation expects data columns in input table"));
    let data_col = left.tracked_col_by_ind(data_idx);
    let log_size = data_col.data_tracked_poly().log_size();
    let perm_mle = prescr_perm::shift_permutation_mle::<B::F>(log_size, 1, true);
    let tracker = data_col.data_tracked_poly().tracker();
    let perm_id = tracker.borrow_mut().track_mat_mv_poly(perm_mle);
    let perm_poly = TrackedPoly::new(Either::Left(perm_id), log_size, tracker);
    let perm_field = Arc::new(Field::new(prescr_perm::PERM_LABEL, DataType::UInt64, false));
    TrackedTable::single_column_with_activator(perm_field, perm_poly, None)
}

fn build_perm_table_verifier<B: SnarkBackend>(
    left: &TrackedTableOracle<B>,
) -> TrackedTableOracle<B> {
    let data_idx = left
        .data_tracked_oracles_indices()
        .first()
        .copied()
        .unwrap_or_else(|| panic!("Sort permutation expects data columns in input table"));
    let data_col = left.tracked_col_oracle_by_ind(data_idx);
    let log_size = data_col.data_tracked_oracle().log_size();
    let perm_oracle = prescr_perm::shift_permutation_oracle::<B::F>(log_size, 1, true);
    let tracker = data_col.data_tracked_oracle().tracker();
    let perm_id = tracker.borrow_mut().track_oracle(perm_oracle);
    let perm_tracked_oracle = TrackedOracle::new(Either::Left(perm_id), tracker, log_size);
    let perm_field = Arc::new(Field::new(prescr_perm::PERM_LABEL, DataType::UInt64, false));
    TrackedTableOracle::single_column_with_activator(perm_field, perm_tracked_oracle, None)
}

fn populate_prescr_perm_payloads_prover<B: SnarkBackend>(
    prescr_perm: &Arc<Node<B>>,
    left: &TrackedTable<B>,
    right: &TrackedTable<B>,
    virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let perm_table = build_perm_table_prover(left);
    let mut perm_payload = match virtualized_ir.payload_for_node(&prescr_perm.id()) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    perm_payload.insert(prescr_perm::LEFT_LABEL.to_string(), left.clone());
    perm_payload.insert(prescr_perm::RIGHT_LABEL.to_string(), right.clone());
    perm_payload.insert(prescr_perm::PERM_LABEL.to_string(), perm_table);
    virtualized_ir.set_payload_for_node(
        prescr_perm.id(),
        Some(PayloadStructure::GadgetPayload(perm_payload)),
    );
    Ok(())
}

fn populate_prescr_perm_payloads_verifier<B: SnarkBackend>(
    prescr_perm: &Arc<Node<B>>,
    left: &TrackedTableOracle<B>,
    right: &TrackedTableOracle<B>,
    virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let perm_table = build_perm_table_verifier(left);
    let mut perm_payload = match virtualized_ir.payload_for_node(&prescr_perm.id()) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    perm_payload.insert(prescr_perm::LEFT_LABEL.to_string(), left.clone());
    perm_payload.insert(prescr_perm::RIGHT_LABEL.to_string(), right.clone());
    perm_payload.insert(prescr_perm::PERM_LABEL.to_string(), perm_table);
    virtualized_ir.set_payload_for_node(
        prescr_perm.id(),
        Some(PayloadStructure::GadgetPayload(perm_payload)),
    );
    Ok(())
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
            return Ok(());
        };
        if payload.get(TABLE_LABEL).is_some() && payload.get(ROTATED_INPUT_LABEL).is_none() {
            panic!("Expected rotated input payload for Sort gadget");
        }
        if let (Some(left), Some(right)) = (
            payload.get(TABLE_LABEL).cloned(),
            payload.get(ROTATED_INPUT_LABEL).cloned(),
        ) {
            populate_prescr_perm_payloads_prover(&self.prescr_perm, &left, &right, virtualized_ir)?;
        }
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
            return Ok(());
        };
        if payload.get(TABLE_LABEL).is_some() && payload.get(ROTATED_INPUT_LABEL).is_none() {
            panic!("Expected rotated input payload for Sort gadget");
        }
        if let (Some(left), Some(right)) = (
            payload.get(TABLE_LABEL).cloned(),
            payload.get(ROTATED_INPUT_LABEL).cloned(),
        ) {
            populate_prescr_perm_payloads_verifier(
                &self.prescr_perm,
                &left,
                &right,
                virtualized_ir,
            )?;
        }
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn verify(
        &self,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new() -> Self {
        let prescr_perm = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::prescr_perm::GadgetNode::new(),
        )));
        Self { prescr_perm }
    }
}

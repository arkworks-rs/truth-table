use std::sync::Arc;

use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::{One, Zero};
use ark_piop::SnarkBackend;
use ark_piop::arithmetic::mat_poly::utils::{build_eq_x_r, build_sparse_eq_x_r};
use ark_piop::verifier::structs::oracle::Oracle;
use ark_piop::{
    prover::ArgProver, prover::structs::polynomial::TrackedPoly, verifier::ArgVerifier,
    verifier::structs::oracle::TrackedOracle,
};
use ark_poly::Polynomial;
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use either::Either;
use indexmap::IndexMap;

use crate::irs::nodes::gadget::utils::{prescr_perm, sign};
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
const FIRST_TIE_LABEL: &str = "tie_0";
pub struct GadgetNode<B: SnarkBackend> {
    num_columns: usize,
    asc: Vec<bool>,
    strict: Vec<bool>,
    prescr_perm: Arc<Node<B>>,
    bool_gadget: Arc<Node<B>>,
    sign_gadgets: Vec<Arc<Node<B>>>,
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
        let mut children = vec![self.prescr_perm.clone(), self.bool_gadget.clone()];
        children.extend(self.sign_gadgets.iter().cloned());
        children
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
        let Some(PayloadStructure::GadgetPayload(mut payload)) =
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
        if let Some(tie_table) = payload.get(TIE_INDICATOR_LABEL).cloned() {
            let tie_table = prepend_first_tie_indicator_prover(&tie_table);
            payload.insert(TIE_INDICATOR_LABEL.to_string(), tie_table.clone());
            // The tie-indicator columns must be boolean, so wire them into the Bool gadget.
            let mut bool_payload = match virtualized_ir.payload_for_node(&self.bool_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            bool_payload.insert(
                crate::irs::nodes::gadget::utils::bool::TABLE_LABEL.to_string(),
                tie_table,
            );
            virtualized_ir.set_payload_for_node(
                self.bool_gadget.id(),
                Some(PayloadStructure::GadgetPayload(bool_payload)),
            );
        }
        if let (Some(tie_table), Some(input_table), Some(rotated_table)) = (
            payload.get(TIE_INDICATOR_LABEL).cloned(),
            payload.get(TABLE_LABEL).cloned(),
            payload.get(ROTATED_INPUT_LABEL).cloned(),
        ) {
            populate_sign_payloads_prover(
                &self.sign_gadgets,
                &tie_table,
                &input_table,
                &rotated_table,
                virtualized_ir,
            )?;
        }
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(payload)));
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
        let Some(PayloadStructure::GadgetPayload(mut payload)) =
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
        if let Some(tie_table) = payload.get(TIE_INDICATOR_LABEL).cloned() {
            let tie_table = prepend_first_tie_indicator_verifier(&tie_table);
            payload.insert(TIE_INDICATOR_LABEL.to_string(), tie_table.clone());
            // The tie-indicator columns must be boolean, so wire them into the Bool gadget.
            let mut bool_payload = match virtualized_ir.payload_for_node(&self.bool_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            bool_payload.insert(
                crate::irs::nodes::gadget::utils::bool::TABLE_LABEL.to_string(),
                tie_table,
            );
            virtualized_ir.set_payload_for_node(
                self.bool_gadget.id(),
                Some(PayloadStructure::GadgetPayload(bool_payload)),
            );
        }
        if let (Some(tie_table), Some(input_table), Some(rotated_table)) = (
            payload.get(TIE_INDICATOR_LABEL).cloned(),
            payload.get(TABLE_LABEL).cloned(),
            payload.get(ROTATED_INPUT_LABEL).cloned(),
        ) {
            populate_sign_payloads_verifier(
                &self.sign_gadgets,
                &tie_table,
                &input_table,
                &rotated_table,
                virtualized_ir,
            )?;
        }
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(payload)));
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        add_tie_monotonicity_zerochecks_prover(prover, gadget_ready_ir, id)?;
        // add_tie_rotation_consistency_zerochecks_prover(prover, gadget_ready_ir, id)
        Ok(())
    }

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        add_tie_monotonicity_zerochecks_verifier(verifier, gadget_ready_ir, id)?;
        // add_tie_rotation_consistency_zerochecks_verifier(verifier, gadget_ready_ir, id)

        Ok(())
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(asc: Vec<bool>, strict: Vec<bool>) -> Self {
        let prescr_perm = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::prescr_perm::GadgetNode::new(),
        )));
        let bool_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::bool::GadgetNode::new(),
        )));
        assert_eq!(asc.len(), strict.len());
        let mut sign_gadgets = Vec::new();
        for _ in 0..asc.len() {
            let sign_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
                sign::SignNode::new(sign::Sign::NonNegative),
            )));
            sign_gadgets.push(sign_gadget);
        }
        Self {
            num_columns: asc.len(),
            prescr_perm,
            bool_gadget,
            asc,
            strict,
            sign_gadgets,
        }
    }
}

fn populate_sign_payloads_prover<B: SnarkBackend>(
    sign_gadgets: &[Arc<Node<B>>],
    tie_table: &TrackedTable<B>,
    input_table: &TrackedTable<B>,
    rotated_table: &TrackedTable<B>,
    virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let tie_indices = tie_table.data_tracked_polys_indices();
    let input_indices = input_table.data_tracked_polys_indices();
    let rotated_indices = rotated_table.data_tracked_polys_indices();
    debug_assert_eq!(
        tie_indices.len(),
        input_indices.len(),
        "Sort sign gadget expects one tie indicator per data column."
    );
    debug_assert_eq!(
        input_indices.len(),
        rotated_indices.len(),
        "Sort sign gadget expects matching input and rotated column counts."
    );
    debug_assert_eq!(
        sign_gadgets.len(),
        tie_indices.len(),
        "Sort gadget expects one sign gadget per tie-indicator column."
    );

    for (((sign_gadget, tie_idx), input_idx), rotated_idx) in sign_gadgets
        .iter()
        .zip(tie_indices.iter().copied())
        .zip(input_indices.iter().copied())
        .zip(rotated_indices.iter().copied())
    {
        let tie_col = tie_table.tracked_col_by_ind(tie_idx);
        let input_col = input_table.tracked_col_by_ind(input_idx);
        let rotated_col = rotated_table.tracked_col_by_ind(rotated_idx);
        let diff_poly = &rotated_col.data_tracked_poly() - &input_col.data_tracked_poly();
        let data_field = input_col
            .field_ref()
            .expect("Expected field ref for Sort sign input");
        let sign_input = TrackedTable::single_column_with_activator(
            data_field,
            diff_poly,
            Some(tie_col.data_tracked_poly()),
        );

        let mut sign_payload = match virtualized_ir.payload_for_node(&sign_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        sign_payload.insert(sign::INPUT_LABEL.to_string(), sign_input);
        virtualized_ir.set_payload_for_node(
            sign_gadget.id(),
            Some(PayloadStructure::GadgetPayload(sign_payload)),
        );
    }
    Ok(())
}

fn populate_sign_payloads_verifier<B: SnarkBackend>(
    sign_gadgets: &[Arc<Node<B>>],
    tie_table: &TrackedTableOracle<B>,
    input_table: &TrackedTableOracle<B>,
    rotated_table: &TrackedTableOracle<B>,
    virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let tie_indices = tie_table.data_tracked_oracles_indices();
    let input_indices = input_table.data_tracked_oracles_indices();
    let rotated_indices = rotated_table.data_tracked_oracles_indices();
    debug_assert_eq!(
        tie_indices.len(),
        input_indices.len(),
        "Sort sign gadget expects one tie indicator per data column."
    );
    debug_assert_eq!(
        input_indices.len(),
        rotated_indices.len(),
        "Sort sign gadget expects matching input and rotated column counts."
    );
    debug_assert_eq!(
        sign_gadgets.len(),
        tie_indices.len(),
        "Sort gadget expects one sign gadget per tie-indicator column."
    );

    for (((sign_gadget, tie_idx), input_idx), rotated_idx) in sign_gadgets
        .iter()
        .zip(tie_indices.iter().copied())
        .zip(input_indices.iter().copied())
        .zip(rotated_indices.iter().copied())
    {
        let tie_col = tie_table.tracked_col_oracle_by_ind(tie_idx);
        let input_col = input_table.tracked_col_oracle_by_ind(input_idx);
        let rotated_col = rotated_table.tracked_col_oracle_by_ind(rotated_idx);
        let diff_oracle = &rotated_col.data_tracked_oracle() - &input_col.data_tracked_oracle();
        let data_field = input_col
            .field_ref()
            .expect("Expected field ref for Sort sign input");
        let sign_input = TrackedTableOracle::single_column_with_activator(
            data_field,
            diff_oracle,
            Some(tie_col.data_tracked_oracle()),
        );

        let mut sign_payload = match virtualized_ir.payload_for_node(&sign_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        sign_payload.insert(sign::INPUT_LABEL.to_string(), sign_input);
        virtualized_ir.set_payload_for_node(
            sign_gadget.id(),
            Some(PayloadStructure::GadgetPayload(sign_payload)),
        );
    }
    Ok(())
}

fn add_tie_monotonicity_zerochecks_prover<B: SnarkBackend>(
    prover: &mut ark_piop::prover::ArgProver<B>,
    gadget_ready_ir: &mut GadgetReadyIr<B>,
    id: crate::irs::nodes::NodeId,
) -> ark_piop::errors::SnarkResult<()> {
    let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
    else {
        return Ok(());
    };
    let Some(tie_table) = payload.get(TIE_INDICATOR_LABEL).cloned() else {
        return Ok(());
    };

    let tie_polys = tie_table.tracked_polys();
    let data_indices: Vec<usize> = tie_table
        .data_tracked_polys_indices()
        .into_iter()
        .filter(|idx| {
            let (field, _) = tie_polys
                .get_index(*idx)
                .expect("tie indicator column index out of bounds");
            field.name() != FIRST_TIE_LABEL
        })
        .collect();
    if data_indices.len() < 2 {
        return Ok(());
    }

    // Enforce ties_i * ties_{i-1} - ties_i = 0, starting from the second column.
    let mut prev = tie_table.tracked_col_by_ind(data_indices[0]);
    for &idx in data_indices.iter().skip(1) {
        let current = tie_table.tracked_col_by_ind(idx);
        let current_poly = current.activated_data_tracked_poly();
        let prev_poly = prev.activated_data_tracked_poly();
        let zero_poly = &(&current_poly * &prev_poly) - &current_poly;
        prover.add_mv_zerocheck_claim(zero_poly.id())?;
        prev = current;
    }
    Ok(())
}

fn add_tie_monotonicity_zerochecks_verifier<B: SnarkBackend>(
    verifier: &mut ark_piop::verifier::ArgVerifier<B>,
    gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
    id: crate::irs::nodes::NodeId,
) -> ark_piop::errors::SnarkResult<()> {
    let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
    else {
        return Ok(());
    };
    let Some(tie_table) = payload.get(TIE_INDICATOR_LABEL).cloned() else {
        return Ok(());
    };

    let tie_oracles = tie_table.tracked_oracles();
    let data_indices: Vec<usize> = tie_table
        .data_tracked_oracles_indices()
        .into_iter()
        .filter(|idx| {
            let (field, _) = tie_oracles
                .get_index(*idx)
                .expect("tie indicator column index out of bounds");
            field.name() != FIRST_TIE_LABEL
        })
        .collect();
    if data_indices.len() < 2 {
        return Ok(());
    }

    // Enforce ties_i * ties_{i-1} - ties_i = 0, starting from the second column.
    let mut prev = tie_table.tracked_col_oracle_by_ind(data_indices[0]);
    for &idx in data_indices.iter().skip(1) {
        let current = tie_table.tracked_col_oracle_by_ind(idx);
        let current_oracle = current.activated_data_tracked_oracle();
        let prev_oracle = prev.activated_data_tracked_oracle();
        let zero_oracle = &(&current_oracle * &prev_oracle) - &current_oracle;
        verifier.add_zerocheck_claim(zero_oracle.id());
        prev = current;
    }
    Ok(())
}

fn add_tie_rotation_consistency_zerochecks_prover<B: SnarkBackend>(
    prover: &mut ark_piop::prover::ArgProver<B>,
    gadget_ready_ir: &mut GadgetReadyIr<B>,
    id: crate::irs::nodes::NodeId,
) -> ark_piop::errors::SnarkResult<()> {
    let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
    else {
        return Ok(());
    };
    let (Some(tie_table), Some(input_table), Some(rotated_table)) = (
        payload.get(TIE_INDICATOR_LABEL).cloned(),
        payload.get(TABLE_LABEL).cloned(),
        payload.get(ROTATED_INPUT_LABEL).cloned(),
    ) else {
        return Ok(());
    };

    println!("{}", tie_table.pretty_string());
    let tie_polys = tie_table.tracked_polys();
    let tie_indices: Vec<usize> = tie_table
        .data_tracked_polys_indices()
        .into_iter()
        .filter(|idx| {
            let (field, _) = tie_polys
                .get_index(*idx)
                .expect("tie indicator column index out of bounds");
            field.name() != FIRST_TIE_LABEL
        })
        .collect();
    let input_indices = input_table.data_tracked_polys_indices();
    let rotated_indices = rotated_table.data_tracked_polys_indices();
    debug_assert_eq!(
        input_indices.len(),
        rotated_indices.len(),
        "Sort gadget expects matching data column counts between input and rotated tables."
    );
    debug_assert_eq!(
        tie_indices.len(),
        input_indices.len(),
        "Sort gadget expects one tie indicator per data column."
    );

    // Enforce tie_i * (input_{i-1} - rotated_{i-1}) = 0 for i > 0.
    for ((tie_idx, input_idx), rotated_idx) in tie_indices
        .iter()
        .copied()
        .skip(1)
        .zip(input_indices.iter().copied())
        .zip(rotated_indices.iter().copied())
    {
        let tie_col = tie_table.tracked_col_by_ind(tie_idx);
        let input_col = input_table.tracked_col_by_ind(input_idx);
        let rotated_col = rotated_table.tracked_col_by_ind(rotated_idx);
        let tie_poly = tie_col.data_tracked_poly();
        let diff_poly = &input_col.data_tracked_poly() - &rotated_col.data_tracked_poly();

        let zero_poly = &tie_poly * &diff_poly;
        prover.add_mv_zerocheck_claim(zero_poly.id())?;
    }
    Ok(())
}

fn add_tie_rotation_consistency_zerochecks_verifier<B: SnarkBackend>(
    verifier: &mut ark_piop::verifier::ArgVerifier<B>,
    gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
    id: crate::irs::nodes::NodeId,
) -> ark_piop::errors::SnarkResult<()> {
    let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
    else {
        return Ok(());
    };
    let (Some(tie_table), Some(input_table), Some(rotated_table)) = (
        payload.get(TIE_INDICATOR_LABEL).cloned(),
        payload.get(TABLE_LABEL).cloned(),
        payload.get(ROTATED_INPUT_LABEL).cloned(),
    ) else {
        return Ok(());
    };

    let tie_oracles = tie_table.tracked_oracles();
    let tie_indices: Vec<usize> = tie_table
        .data_tracked_oracles_indices()
        .into_iter()
        .filter(|idx| {
            let (field, _) = tie_oracles
                .get_index(*idx)
                .expect("tie indicator column index out of bounds");
            field.name() != FIRST_TIE_LABEL
        })
        .collect();
    let input_indices = input_table.data_tracked_oracles_indices();
    let rotated_indices = rotated_table.data_tracked_oracles_indices();
    debug_assert_eq!(
        input_indices.len(),
        rotated_indices.len(),
        "Sort gadget expects matching data column counts between input and rotated tables."
    );
    debug_assert_eq!(
        tie_indices.len(),
        input_indices.len(),
        "Sort gadget expects one tie indicator per data column."
    );

    // Enforce tie_i * (input_{i-1} - rotated_{i-1}) = 0 for i > 0.
    for ((tie_idx, input_idx), rotated_idx) in tie_indices
        .iter()
        .copied()
        .skip(1)
        .zip(input_indices.iter().copied())
        .zip(rotated_indices.iter().copied())
    {
        let tie_col = tie_table.tracked_col_oracle_by_ind(tie_idx);
        let input_col = input_table.tracked_col_oracle_by_ind(input_idx);
        let rotated_col = rotated_table.tracked_col_oracle_by_ind(rotated_idx);

        let tie_oracle = tie_col.data_tracked_oracle();
        let diff_oracle = &input_col.data_tracked_oracle() - &rotated_col.data_tracked_oracle();
        let zero_oracle = &tie_oracle * &diff_oracle;
        verifier.add_zerocheck_claim(zero_oracle.id());
    }
    Ok(())
}

fn prepend_first_tie_indicator_prover<B: SnarkBackend>(table: &TrackedTable<B>) -> TrackedTable<B> {
    if table
        .tracked_polys_iter()
        .any(|(field, _)| field.name() == FIRST_TIE_LABEL)
    {
        return table.clone();
    }

    let data_idx = table
        .data_tracked_polys_indices()
        .first()
        .copied()
        .unwrap_or_else(|| panic!("Tie indicator table must have data columns"));
    let data_col = table.tracked_col_by_ind(data_idx);
    let num_vars = data_col.data_tracked_poly().log_size();
    let tracker = data_col.data_tracked_poly().tracker();
    let mut prover = ArgProver::new_from_tracker_rc(tracker.clone());

    // Build the special first tie column: 1 - eq_x_r(1^n).
    let one_tracked_poly = prover.track_mat_mv_cnst_poly(num_vars, B::F::one());
    let last_eq_poly =
        build_eq_x_r(&vec![B::F::one(); num_vars]).expect("build_eq_x_r should succeed");
    let last_eq_id = tracker
        .borrow_mut()
        .track_mat_mv_poly(last_eq_poly.as_ref().clone());
    let tracked_last_eq_poly = TrackedPoly::new(Either::Left(last_eq_id), num_vars, tracker);
    let first_tie_poly = &one_tracked_poly - &tracked_last_eq_poly;

    let first_tie_field = Arc::new(Field::new(FIRST_TIE_LABEL, DataType::Boolean, false));
    let mut tracked_polys = IndexMap::new();
    tracked_polys.insert(first_tie_field.clone(), first_tie_poly);
    for (field, poly) in table.tracked_polys_iter() {
        tracked_polys.insert(field.clone(), poly.clone());
    }

    let schema = table.schema_ref().map(|schema| {
        let fields = tracked_polys
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    let schema = schema.or_else(|| {
        Some(Schema::new(
            tracked_polys
                .keys()
                .map(|field| field.as_ref().clone())
                .collect::<Vec<_>>(),
        ))
    });
    TrackedTable::new(schema, tracked_polys, table.log_size())
}

fn prepend_first_tie_indicator_verifier<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
) -> TrackedTableOracle<B> {
    if table
        .tracked_oracles_iter()
        .any(|(field, _)| field.name() == FIRST_TIE_LABEL)
    {
        return table.clone();
    }

    let data_idx = table
        .data_tracked_oracles_indices()
        .first()
        .copied()
        .unwrap_or_else(|| panic!("Tie indicator table must have data columns"));
    let data_col = table.tracked_col_oracle_by_ind(data_idx);
    let num_vars = data_col.data_tracked_oracle().log_size();
    let tracker = data_col.data_tracked_oracle().tracker();
    let mut verifier = ArgVerifier::new_from_tracker_rc(tracker.clone());

    // Build the special first tie column: 1 - eq_x_r(1^n).
    let one_tracked_oracle = verifier.track_mat_mv_cnst_oracle(num_vars, B::F::one());
    let last_eq_sparse = build_sparse_eq_x_r(&vec![B::F::one(); num_vars])
        .expect("build_sparse_eq_x_r should succeed");
    let last_eq_oracle = Oracle::new_multivariate(num_vars, move |point: Vec<B::F>| {
        Ok(last_eq_sparse.evaluate(&point))
    });
    let last_eq_id = tracker.borrow_mut().track_oracle(last_eq_oracle);
    let tracked_last_eq_oracle = TrackedOracle::new(Either::Left(last_eq_id), tracker, num_vars);
    let first_tie_oracle = &one_tracked_oracle - &tracked_last_eq_oracle;

    let first_tie_field = Arc::new(Field::new(FIRST_TIE_LABEL, DataType::Boolean, false));
    let mut tracked_oracles = IndexMap::new();
    tracked_oracles.insert(first_tie_field.clone(), first_tie_oracle);
    for (field, oracle) in table.tracked_oracles_iter() {
        tracked_oracles.insert(field.clone(), oracle.clone());
    }

    let schema = table.schema_ref().map(|schema| {
        let fields = tracked_oracles
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    let schema = schema.or_else(|| {
        Some(Schema::new(
            tracked_oracles
                .keys()
                .map(|field| field.as_ref().clone())
                .collect::<Vec<_>>(),
        ))
    });
    TrackedTableOracle::new(schema, tracked_oracles, table.log_size())
}

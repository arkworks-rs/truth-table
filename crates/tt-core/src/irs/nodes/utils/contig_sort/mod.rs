use crate::session::session_context;
use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_FIELD, ROW_ID_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_ff::{One, Zero};
use ark_piop::SnarkBackend;
use ark_piop::arithmetic::mat_poly::utils::{build_eq_x_r, build_sparse_eq_x_r};
use ark_piop::prover::structs::polynomial::get_or_insert_shift_poly;
use ark_piop::verifier::structs::oracle::Oracle;
use ark_piop::verifier::structs::oracle::get_or_insert_shift_oracle;
use ark_piop::{
    prover::ArgProver, prover::structs::polynomial::TrackedPoly, verifier::ArgVerifier,
    verifier::structs::oracle::TrackedOracle,
};
use ark_poly::Polynomial;
use datafusion::arrow::{
    array::{ArrayRef, BooleanArray, Int64Array},
    compute::{concat, concat_batches},
    datatypes::{DataType, Field, IntervalUnit, Schema},
    record_batch::RecordBatch,
};
use datafusion::datasource::MemTable;
use datafusion_common::{DFSchema, DataFusionError, ScalarValue};
use either::Either;
use indexmap::IndexMap;

use crate::irs::nodes::utils::{neq, prescr_perm, sign};
use crate::{
    irs::{
        nodes::{
            IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps,
            utils::contig_sort::hints::{populate_rotated, populate_tie_and_diff},
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
pub const DIFF_INPUT_LABEL: &str = "__diff_input__";
const FIRST_TIE_LABEL: &str = "tie_0";

pub enum SortConfig {
    Uniform(UniformConfig),
    PerColumn(PerColumnConfig),
}

pub struct UniformConfig {
    pub asc: bool,
    pub strict: bool,
}

pub struct PerColumnConfig {
    pub sort_specs: Vec<(String, bool, bool)>,
    pub strict: bool,
}

/// Enforces that a table is sorted according to its sort config.
pub struct GadgetNode<B: SnarkBackend> {
    prescr_perm: Arc<Node<B>>,
    bool_gadget: Arc<Node<B>>,
    sign_gadget: Arc<Node<B>>,
    neq_gadget: Arc<Node<B>>,
    sort_config: SortConfig,
    strip_row_id: bool,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Contiguous Sort".to_string()
    }

    fn display(&self) -> String {
        let name = self.name();
        crate::irs::nodes::display_with_inputs(&name, &self.children())
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![
            self.prescr_perm.clone(),
            self.bool_gadget.clone(),
            self.sign_gadget.clone(),
            self.neq_gadget.clone(),
        ]
    }
}

fn build_perm_table_prover<B: SnarkBackend>(
    prover: &mut ark_piop::prover::ArgProver<B>,
    left: &TrackedTable<B>,
) -> TrackedTable<B> {
    let data_poly = if let Some(data_idx) = left.data_tracked_polys_indices().first().copied() {
        left.tracked_col_by_ind(data_idx).data_tracked_poly()
    } else if let Some(activator) = left.activator_tracked_poly() {
        activator
    } else if let Some(col) = left.all_tracked_cols().first() {
        col.data_tracked_poly()
    } else {
        panic!("Sort permutation expects at least one column in input table");
    };
    let log_size = data_poly.log_size();
    let perm_poly = get_or_insert_shift_poly(prover, log_size, 1, true);
    let perm_field = Arc::new(Field::new(prescr_perm::PERM_LABEL, DataType::UInt64, false));
    TrackedTable::single_column_with_activator(perm_field, perm_poly, None)
}

fn build_perm_table_verifier<B: SnarkBackend>(
    verifier: &mut ark_piop::verifier::ArgVerifier<B>,
    left: &TrackedTableOracle<B>,
) -> TrackedTableOracle<B> {
    let data_oracle = if let Some(data_idx) = left.data_tracked_oracles_indices().first().copied() {
        left.tracked_col_oracle_by_ind(data_idx)
            .data_tracked_oracle()
    } else if let Some(activator) = left.activator_tracked_poly() {
        activator
    } else if let Some(col) = left.all_tracked_col_oracles().first() {
        col.data_tracked_oracle()
    } else {
        panic!("Sort permutation expects at least one column in input table");
    };
    let log_size = data_oracle.log_size();
    let perm_tracked_oracle = get_or_insert_shift_oracle(verifier, log_size, 1, true);
    let perm_field = Arc::new(Field::new(prescr_perm::PERM_LABEL, DataType::UInt64, false));
    TrackedTableOracle::single_column_with_activator(perm_field, perm_tracked_oracle, None)
}

fn populate_prescr_perm_payloads_prover<B: SnarkBackend>(
    prescr_perm: &Arc<Node<B>>,
    prover: &mut ark_piop::prover::ArgProver<B>,
    left: &TrackedTable<B>,
    right: &TrackedTable<B>,
    virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let perm_table = build_perm_table_prover(prover, left);
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
    verifier: &mut ark_piop::verifier::ArgVerifier<B>,
    left: &TrackedTableOracle<B>,
    right: &TrackedTableOracle<B>,
    virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let perm_table = build_perm_table_verifier(verifier, left);
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

fn initialize_gadget_plans<B: SnarkBackend>(
    node: &GadgetNode<B>,
    id: crate::irs::nodes::NodeId,
    planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    is_verifier: bool,
) -> ark_piop::errors::SnarkResult<()> {
    let mut gadget_payload = match planned_ir.payload_for_node(&id) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => return Ok(()),
    };
    let input_hint = match gadget_payload.get(TABLE_LABEL) {
        Some(hint_df) => hint_df.clone(),
        None => return Ok(()),
    };
    let sort_specs = sort_specs_for_hint(&node.sort_config, &input_hint);
    let sorted_input_hint = if is_verifier {
        build_schema_only_hint_from_existing(&input_hint)
    } else {
        let sorted_df = crate::irs::nodes::utils::contig_sort::hints::sort_input_for_contig_sort(
            &input_hint,
            &sort_specs,
        )
        .expect("contig sort ordering should succeed");
        let padded_df =
            pad_df_to_power_of_two(sorted_df).expect("contig sort input padding should succeed");
        let mut should_materialize = IndexMap::new();
        for field in padded_df.schema().fields() {
            let materialized = input_hint
                .field_materialization_iter()
                .find(|(orig_field, _)| orig_field.name() == field.name())
                .map(|(_, materialized)| *materialized)
                .unwrap_or(true);
            should_materialize.insert(field.clone(), materialized);
        }
        crate::irs::nodes::hints::HintDF::new(padded_df, should_materialize)
    };
    if is_verifier {
        let ordered_data_fields = ordered_data_fields_for_hint(&sorted_input_hint, &sort_specs);
        gadget_payload.insert(
            ROTATED_INPUT_LABEL.to_string(),
            build_verifier_rotated_hint(&sorted_input_hint),
        );
        if let Some(tie_hint) = build_verifier_tie_hint_from_ordered(&ordered_data_fields) {
            gadget_payload.insert(TIE_INDICATOR_LABEL.to_string(), tie_hint);
        }
        if let Some(diff_hint) = build_verifier_diff_hint_from_ordered(&ordered_data_fields) {
            gadget_payload.insert(DIFF_INPUT_LABEL.to_string(), diff_hint);
        }
    } else {
        populate_rotated(&mut gadget_payload, &sorted_input_hint, &sort_specs, false);
        populate_tie_and_diff(&mut gadget_payload, &sorted_input_hint, &sort_specs);
    }
    let input_hint = if node.strip_row_id {
        // Strip row-id before storing to avoid exposing it in gadget payloads.
        if is_verifier {
            strip_row_id_schema_only_hint(&sorted_input_hint)
        } else {
            crate::irs::nodes::hints::strip_row_id_from_hint(&sorted_input_hint)
        }
    } else {
        sorted_input_hint.clone()
    };
    gadget_payload.insert(TABLE_LABEL.to_string(), input_hint);
    planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));
    Ok(())
}

fn strip_row_id_schema_only_hint(
    hint: &crate::irs::nodes::hints::HintDF,
) -> crate::irs::nodes::hints::HintDF {
    let fields: Vec<Field> = hint
        .data_frame()
        .schema()
        .fields()
        .iter()
        .filter(|field| field.name() != ROW_ID_COL_NAME)
        .map(|field| field.as_ref().clone())
        .collect();
    if fields.len() == hint.data_frame().schema().fields().len() {
        return hint.clone();
    }

    let df = crate::irs::nodes::hints::schema_only_df(fields.clone());
    let mut should_materialize = IndexMap::new();
    for field in df.schema().fields() {
        let materialized = hint
            .field_materialization_iter()
            .find(|(orig_field, _)| orig_field.name() == field.name())
            .map(|(_, materialized)| *materialized)
            .unwrap_or(true);
        should_materialize.insert(field.clone(), materialized);
    }
    crate::irs::nodes::hints::HintDF::new_assume_normalized(df, should_materialize)
}

fn build_schema_only_hint_from_existing(
    hint: &crate::irs::nodes::hints::HintDF,
) -> crate::irs::nodes::hints::HintDF {
    let fields: Vec<Field> = hint
        .data_frame()
        .schema()
        .fields()
        .iter()
        .map(|field| field.as_ref().clone())
        .collect();
    let df = crate::irs::nodes::hints::schema_only_df(fields);
    let mut should_materialize = IndexMap::new();
    for field in df.schema().fields() {
        let materialized = hint
            .field_materialization_iter()
            .find(|(orig_field, _)| orig_field.name() == field.name())
            .map(|(_, materialized)| *materialized)
            .unwrap_or(true);
        should_materialize.insert(field.clone(), materialized);
    }
    crate::irs::nodes::hints::HintDF::new_assume_normalized(df, should_materialize)
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        initialize_gadget_plans(self, id, planned_ir, false)
    }
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
        prover: &mut ark_piop::prover::ArgProver<B>,
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
        let input_table = payload.get(TABLE_LABEL);
        let rotated_table = payload.get(ROTATED_INPUT_LABEL);
        let diff_table = payload.get(DIFF_INPUT_LABEL);
        let tie_table = payload.get(TIE_INDICATOR_LABEL);

        if let (Some(left), Some(right)) = (input_table, rotated_table) {
            populate_prescr_perm_payloads_prover(
                &self.prescr_perm,
                prover,
                left,
                right,
                virtualized_ir,
            )?;
        }
        let updated_tie_table = input_table.map(|input_table| {
            prepend_first_tie_indicator_prover(prover, tie_table, input_table.log_size())
        });
        if let Some(tie_table) = updated_tie_table.as_ref() {
            // The tie-indicator columns must be boolean, so wire them into the Bool gadget.
            let mut bool_payload = match virtualized_ir.payload_for_node(&self.bool_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            bool_payload.insert(
                crate::irs::nodes::utils::bool::TABLE_LABEL.to_string(),
                tie_table.clone(),
            );
            virtualized_ir.set_payload_for_node(
                self.bool_gadget.id(),
                Some(PayloadStructure::GadgetPayload(bool_payload)),
            );
        }
        if let (Some(tie_table), Some(input_table), Some(rotated_table)) =
            (updated_tie_table.as_ref(), input_table, rotated_table)
        {
            let sort_specs = sort_specs_for_table_prover(&self.sort_config, input_table);
            populate_sign_payloads_prover(
                &self.sign_gadget,
                &self.sort_config,
                &sort_specs,
                diff_table,
                tie_table,
                input_table,
                rotated_table,
                virtualized_ir,
            )?;
            populate_neq_payloads_prover(
                &self.neq_gadget,
                &sort_specs,
                tie_table,
                input_table,
                rotated_table,
                virtualized_ir,
            )?;
        }
        if let Some(tie_table) = updated_tie_table {
            payload.insert(TIE_INDICATOR_LABEL.to_string(), tie_table);
        }
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(payload)));
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        initialize_gadget_plans(self, id, planned_ir, true)
    }
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
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(mut payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };
        let input_table = payload.get(TABLE_LABEL);
        let rotated_table = payload.get(ROTATED_INPUT_LABEL);
        let diff_table = payload.get(DIFF_INPUT_LABEL);
        let tie_table = payload.get(TIE_INDICATOR_LABEL);

        if input_table.is_some() && rotated_table.is_none() {
            panic!("Expected rotated input payload for Sort gadget");
        }
        if let (Some(left), Some(right)) = (input_table, rotated_table) {
            populate_prescr_perm_payloads_verifier(
                &self.prescr_perm,
                verifier,
                left,
                right,
                virtualized_ir,
            )?;
        }
        let updated_tie_table_owned = input_table.map(|input_table| {
            prepend_first_tie_indicator_verifier(verifier, tie_table, input_table.log_size())
        });
        if let Some(tie_table) = updated_tie_table_owned.as_ref() {
            // The tie-indicator columns must be boolean, so wire them into the Bool gadget.
            let mut bool_payload = match virtualized_ir.payload_for_node(&self.bool_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            bool_payload.insert(
                crate::irs::nodes::utils::bool::TABLE_LABEL.to_string(),
                tie_table.clone(),
            );
            virtualized_ir.set_payload_for_node(
                self.bool_gadget.id(),
                Some(PayloadStructure::GadgetPayload(bool_payload)),
            );
        }
        if let (Some(tie_table), Some(input_table), Some(rotated_table)) =
            (updated_tie_table_owned.as_ref(), input_table, rotated_table)
        {
            let sort_specs = sort_specs_for_table_verifier(&self.sort_config, input_table);
            populate_sign_payloads_verifier(
                &self.sign_gadget,
                &self.sort_config,
                &sort_specs,
                diff_table,
                tie_table,
                input_table,
                rotated_table,
                virtualized_ir,
            )?;
            populate_neq_payloads_verifier(
                &self.neq_gadget,
                &sort_specs,
                tie_table,
                input_table,
                rotated_table,
                virtualized_ir,
            )?;
        }
        if let Some(tie_table) = updated_tie_table_owned {
            payload.insert(TIE_INDICATOR_LABEL.to_string(), tie_table);
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
        add_tie_rotation_consistency_zerochecks_prover(prover, gadget_ready_ir, id)?;
        Ok(())
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        add_tie_monotonicity_zerochecks_verifier(verifier, gadget_ready_ir, id)?;
        add_tie_rotation_consistency_zerochecks_verifier(verifier, gadget_ready_ir, id)?;

        Ok(())
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(sort_config: SortConfig) -> Self {
        Self::new_internal(sort_config, true)
    }

    pub fn new_preserve_row_id(sort_config: SortConfig) -> Self {
        Self::new_internal(sort_config, false)
    }

    fn new_internal(sort_config: SortConfig, strip_row_id: bool) -> Self {
        let prescr_perm = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::utils::prescr_perm::GadgetNode::new(),
        )));
        let bool_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::utils::bool::GadgetNode::new(),
        )));
        let neq_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::utils::neq::GadgetNode::new(),
        )));
        let sign_gadget = build_sign_gadget::<B>(&sort_config);
        Self {
            prescr_perm,
            bool_gadget,
            sign_gadget,
            neq_gadget,
            sort_config,
            strip_row_id,
        }
    }
}

// Use a forward-difference sign check so contig-sort only enforces monotonicity.
fn sign_for_column(_is_asc: bool, strict_for_col: bool) -> sign::Sign {
    if strict_for_col {
        sign::Sign::Positive
    } else {
        sign::Sign::NonNegative
    }
}

fn build_sign_gadget<B: SnarkBackend>(sort_config: &SortConfig) -> Arc<Node<B>> {
    let sign_config = match sort_config {
        SortConfig::Uniform(config) => {
            if config.strict {
                sign::SignConfig::SemiUniform(sign::Sign::NonNegative, sign::Sign::Positive)
            } else {
                sign::SignConfig::Uniform(sign::Sign::NonNegative)
            }
        }
        SortConfig::PerColumn(config) => {
            let last_idx = config.sort_specs.len().saturating_sub(1);
            let signs = config
                .sort_specs
                .iter()
                .enumerate()
                .map(|(idx, (_, asc, _))| {
                    let strict_for_col = config.strict && idx == last_idx;
                    sign_for_column(*asc, strict_for_col)
                })
                .collect();
            sign::SignConfig::PerColumn(signs)
        }
    };
    Arc::new(Node::<B>::Gadget(Arc::new(sign::SignNode::new(
        sign_config,
    ))))
}

fn normalize_sort_name(name: &str) -> String {
    name.rsplit('.').next().unwrap_or(name).to_string()
}

fn sort_specs_for_hint(
    sort_config: &SortConfig,
    input_hint: &crate::irs::nodes::hints::HintDF,
) -> Vec<(String, bool, bool)> {
    match sort_config {
        SortConfig::PerColumn(config) => config.sort_specs.clone(),
        SortConfig::Uniform(config) => input_hint
            .data_frame()
            .schema()
            .fields()
            .iter()
            .filter(|field| !arithmetic::is_system_column(field.name()))
            .map(|field| (field.name().to_string(), config.asc, true))
            .collect(),
    }
}

fn build_empty_hint_df_with_fields(
    fields: Vec<Field>,
    materialized: bool,
) -> crate::irs::nodes::hints::HintDF {
    let df = crate::irs::nodes::hints::schema_only_df(fields);
    let mut should_materialize = IndexMap::new();
    for field in df.schema().fields() {
        should_materialize.insert(field.clone(), materialized);
    }
    crate::irs::nodes::hints::HintDF::new_assume_normalized(df, should_materialize)
}

fn ordered_data_fields_for_hint(
    hint: &crate::irs::nodes::hints::HintDF,
    sort_specs: &[(String, bool, bool)],
) -> Vec<Field> {
    let data_fields: Vec<Field> = hint
        .data_frame()
        .schema()
        .fields()
        .iter()
        .filter(|field| !arithmetic::is_system_column(field.name()))
        .map(|field| field.as_ref().clone())
        .collect();

    if sort_specs.is_empty() {
        return data_fields;
    }

    let mut ordered = Vec::with_capacity(data_fields.len());
    for (name, _, _) in sort_specs {
        let normalized = normalize_sort_name(name);
        if let Some(field) = data_fields
            .iter()
            .find(|field| normalize_sort_name(field.name()) == normalized)
        {
            ordered.push(field.clone());
        }
    }
    if ordered.len() == data_fields.len() {
        ordered
    } else {
        data_fields
    }
}

fn build_verifier_rotated_hint(
    input_hint: &crate::irs::nodes::hints::HintDF,
) -> crate::irs::nodes::hints::HintDF {
    let fields: Vec<Field> = input_hint
        .data_frame()
        .schema()
        .fields()
        .iter()
        .filter(|field| field.name() != ROW_ID_COL_NAME)
        .map(|field| field.as_ref().clone())
        .collect();
    build_empty_hint_df_with_fields(fields, true)
}

fn build_verifier_tie_hint_from_ordered(
    ordered_data_fields: &[Field],
) -> Option<crate::irs::nodes::hints::HintDF> {
    if ordered_data_fields.len() < 2 {
        return None;
    }
    let fields = (1..ordered_data_fields.len())
        .map(|idx| Field::new(format!("tie_{idx}"), DataType::Boolean, true))
        .collect();
    Some(build_empty_hint_df_with_fields(fields, true))
}

/// The Sign type that range-checks the adjacent difference `rotated - input`
/// of a sort key (paper PIOP 7, step 3f). Signed values encode as field
/// negations, so the difference is the integer one, and a non-decreasing pair
/// gives a value in `[0, 2^w)` for the key's unsigned width `w`.
///
/// `None` when the encoding does not preserve the key's order (strings,
/// binary, `Decimal256`). Such a key is compared through a committed
/// sign-only diff in `{0, 1, 2}`, which is not bound to the key.
pub(crate) fn difference_sign_type(data_type: &DataType) -> Option<DataType> {
    match data_type {
        DataType::Boolean | DataType::Int8 | DataType::UInt8 => Some(DataType::UInt8),
        DataType::Int16 | DataType::UInt16 => Some(DataType::UInt16),
        DataType::Int32
        | DataType::UInt32
        | DataType::Date32
        | DataType::Time32(_)
        | DataType::Interval(IntervalUnit::YearMonth) => Some(DataType::UInt32),
        DataType::Int64
        | DataType::UInt64
        | DataType::Date64
        | DataType::Time64(_)
        | DataType::Timestamp(..)
        | DataType::Duration(_) => Some(DataType::UInt64),
        DataType::Decimal128(..) => Some(data_type.clone()),
        _ => None,
    }
}

fn build_verifier_diff_hint_from_ordered(
    ordered_data_fields: &[Field],
) -> Option<crate::irs::nodes::hints::HintDF> {
    let fields: Vec<Field> = ordered_data_fields
        .iter()
        .filter(|field| difference_sign_type(field.data_type()).is_none())
        .map(|field| Field::new(field.name(), DataType::UInt8, true))
        .collect();
    (!fields.is_empty()).then(|| build_empty_hint_df_with_fields(fields, true))
}

fn sort_specs_for_table_prover<B: SnarkBackend>(
    sort_config: &SortConfig,
    input_table: &TrackedTable<B>,
) -> Vec<(String, bool, bool)> {
    match sort_config {
        SortConfig::PerColumn(config) => config.sort_specs.clone(),
        SortConfig::Uniform(config) => input_table
            .data_tracked_polys_indices()
            .into_iter()
            .filter(|idx| {
                let field = input_table
                    .tracked_col_by_ind(*idx)
                    .field_ref()
                    .expect("Expected field ref for Sort input");
                // Skip __row_id__ and auxiliary segments (e.g. __length): there is
                // one tie indicator per logical sort key, so only primary segments
                // belong here.
                field.name() != ROW_ID_COL_NAME
                    && arithmetic::encoding::segment_base_name(field.name()).is_none()
            })
            .map(|idx| {
                let field = input_table
                    .tracked_col_by_ind(idx)
                    .field_ref()
                    .expect("Expected field ref for Sort input");
                (field.name().to_string(), config.asc, true)
            })
            .collect(),
    }
}

fn sort_specs_for_table_verifier<B: SnarkBackend>(
    sort_config: &SortConfig,
    input_table: &TrackedTableOracle<B>,
) -> Vec<(String, bool, bool)> {
    match sort_config {
        SortConfig::PerColumn(config) => config.sort_specs.clone(),
        SortConfig::Uniform(config) => input_table
            .data_tracked_oracles_indices()
            .into_iter()
            .filter(|idx| {
                let field = input_table
                    .tracked_col_oracle_by_ind(*idx)
                    .field_ref()
                    .expect("Expected field ref for Sort input");
                field.name() != ROW_ID_COL_NAME
                    && arithmetic::encoding::segment_base_name(field.name()).is_none()
            })
            .map(|idx| {
                let field = input_table
                    .tracked_col_oracle_by_ind(idx)
                    .field_ref()
                    .expect("Expected field ref for Sort input");
                (field.name().to_string(), config.asc, true)
            })
            .collect(),
    }
}

fn ordered_data_indices_prover<B: SnarkBackend>(
    table: &TrackedTable<B>,
    sort_specs: &[(String, bool, bool)],
) -> Vec<usize> {
    let data_indices: Vec<usize> = non_row_id_data_indices_prover(table);
    if sort_specs.is_empty() {
        return data_indices;
    }
    let mut ordered = Vec::with_capacity(data_indices.len());
    for (name, _, _) in sort_specs {
        let normalized = normalize_sort_name(name);
        if let Some(idx) = data_indices.iter().copied().find(|idx| {
            let field = table
                .tracked_col_by_ind(*idx)
                .field_ref()
                .expect("Expected field ref for Sort input");
            normalize_sort_name(field.name()) == normalized
        }) {
            ordered.push(idx);
        }
    }
    if ordered.len() == sort_specs.len() {
        ordered
    } else {
        data_indices
    }
}

fn ordered_data_indices_verifier<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    sort_specs: &[(String, bool, bool)],
) -> Vec<usize> {
    let data_indices: Vec<usize> = non_row_id_data_indices_verifier(table);
    if sort_specs.is_empty() {
        return data_indices;
    }
    let mut ordered = Vec::with_capacity(data_indices.len());
    for (name, _, _) in sort_specs {
        let normalized = normalize_sort_name(name);
        if let Some(idx) = data_indices.iter().copied().find(|idx| {
            let field = table
                .tracked_col_oracle_by_ind(*idx)
                .field_ref()
                .expect("Expected field ref for Sort input");
            normalize_sort_name(field.name()) == normalized
        }) {
            ordered.push(idx);
        }
    }
    if ordered.len() == sort_specs.len() {
        ordered
    } else {
        data_indices
    }
}

fn non_row_id_data_indices_prover<B: SnarkBackend>(table: &TrackedTable<B>) -> Vec<usize> {
    table
        .data_tracked_polys_indices()
        .into_iter()
        .filter(|idx| {
            let field = table
                .tracked_col_by_ind(*idx)
                .field_ref()
                .expect("Expected field ref for Sort input");
            field.name() != ROW_ID_COL_NAME
        })
        .collect()
}

fn non_row_id_data_indices_verifier<B: SnarkBackend>(table: &TrackedTableOracle<B>) -> Vec<usize> {
    table
        .data_tracked_oracles_indices()
        .into_iter()
        .filter(|idx| {
            let field = table
                .tracked_col_oracle_by_ind(*idx)
                .field_ref()
                .expect("Expected field ref for Sort input");
            field.name() != ROW_ID_COL_NAME
        })
        .collect()
}

fn sort_is_asc(sort_specs: &[(String, bool, bool)], col_name: &str) -> bool {
    sort_specs
        .iter()
        .find(|(name, _, _)| normalize_sort_name(name) == col_name)
        .map(|(_, asc, _)| *asc)
        .unwrap_or(true)
}

#[allow(clippy::too_many_arguments)]
fn populate_sign_payloads_prover<B: SnarkBackend>(
    sign_gadget: &Arc<Node<B>>,
    sort_config: &SortConfig,
    sort_specs: &[(String, bool, bool)],
    diff_table: Option<&TrackedTable<B>>,
    tie_table: &TrackedTable<B>,
    input_table: &TrackedTable<B>,
    rotated_table: &TrackedTable<B>,
    virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let tie_indices = tie_table.data_tracked_polys_indices();
    let input_indices = ordered_data_indices_prover(input_table, sort_specs);
    let rotated_indices = ordered_data_indices_prover(rotated_table, sort_specs);
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

    let mut data_cols = IndexMap::new();
    let input_activator = input_table.activator_tracked_poly();
    let rotated_activator = rotated_table.activator_tracked_poly();
    let combined_activator = match (input_activator, rotated_activator) {
        (Some(left), Some(right)) => Some(&left * &right),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    };

    for (pos, ((tie_idx, input_idx), rotated_idx)) in tie_indices
        .iter()
        .copied()
        .zip(input_indices.iter().copied())
        .zip(rotated_indices.iter().copied())
        .enumerate()
    {
        let tie_col = tie_table.tracked_col_by_ind(tie_idx);
        let input_col = input_table.tracked_col_by_ind(input_idx);
        let rotated_col = rotated_table.tracked_col_by_ind(rotated_idx);
        let col_name = input_col
            .field_ref()
            .expect("Expected field ref for Sort sign input")
            .name()
            .to_string();
        let col_name = normalize_sort_name(&col_name);
        let is_asc = sort_is_asc(sort_specs, &col_name);
        let sign = match sort_config {
            SortConfig::Uniform(config) => sign_for_column(config.asc, config.strict),
            SortConfig::PerColumn(config) => {
                let strict_for_col = config.strict && pos + 1 == input_indices.len();
                sign_for_column(is_asc, strict_for_col)
            }
        };

        let input_field = input_col
            .field_ref()
            .expect("Expected field ref for Sort sign input");
        let (diff_poly, diff_field) = match difference_sign_type(input_field.data_type()) {
            Some(sign_type) => {
                let input_poly = input_col.data_tracked_poly();
                let rotated_poly = rotated_col.data_tracked_poly();
                let diff_poly = if is_asc {
                    &rotated_poly - &input_poly
                } else {
                    &input_poly - &rotated_poly
                };
                (diff_poly, Field::new(input_field.name(), sign_type, false))
            }
            None => {
                let diff_col = diff_table
                    .and_then(|table| {
                        table
                            .data_tracked_polys_indices()
                            .into_iter()
                            .map(|idx| table.tracked_col_by_ind(idx))
                            .find(|col| {
                                col.field_ref().is_some_and(|field| {
                                    normalize_sort_name(field.name()) == col_name
                                })
                            })
                    })
                    .expect("Expected a sign-only diff column for Sort key");
                let diff_field = diff_col
                    .field_ref()
                    .expect("Expected field ref for Sort diff input")
                    .as_ref()
                    .clone();
                // Undo the `+1` shift of the stored `{0, 1, 2}`.
                (
                    diff_col.data_tracked_poly().sub_scalar_poly(B::F::one()),
                    diff_field,
                )
            }
        };

        let tie_poly = tie_col.data_tracked_poly();
        let one_poly = TrackedPoly::new(
            Either::Right(B::F::one()),
            tie_poly.log_size(),
            tie_poly.tracker(),
        );
        let masked_diff = match sign {
            sign::Sign::Positive | sign::Sign::Negative => {
                &(&diff_poly * &tie_poly) + &(&(&one_poly - &tie_poly) * &one_poly)
            }
            _ => &diff_poly * &tie_poly,
        };
        data_cols.insert(Arc::new(diff_field), masked_diff);
    }

    if let Some(activator) = combined_activator {
        data_cols.insert(ACTIVATOR_FIELD.clone(), activator);
    }

    let sign_input = TrackedTable::new(None, data_cols, input_table.log_size());
    let mut sign_payload = match virtualized_ir.payload_for_node(&sign_gadget.id()) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    sign_payload.insert(sign::INPUT_LABEL.to_string(), sign_input);
    virtualized_ir.set_payload_for_node(
        sign_gadget.id(),
        Some(PayloadStructure::GadgetPayload(sign_payload)),
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn populate_sign_payloads_verifier<B: SnarkBackend>(
    sign_gadget: &Arc<Node<B>>,
    sort_config: &SortConfig,
    sort_specs: &[(String, bool, bool)],
    diff_table: Option<&TrackedTableOracle<B>>,
    tie_table: &TrackedTableOracle<B>,
    input_table: &TrackedTableOracle<B>,
    rotated_table: &TrackedTableOracle<B>,
    virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let tie_indices = tie_table.data_tracked_oracles_indices();
    let input_indices = ordered_data_indices_verifier(input_table, sort_specs);
    let rotated_indices = ordered_data_indices_verifier(rotated_table, sort_specs);
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

    let mut data_cols = IndexMap::new();
    let input_activator = input_table.activator_tracked_poly();
    let rotated_activator = rotated_table.activator_tracked_poly();
    let combined_activator = match (input_activator, rotated_activator) {
        (Some(left), Some(right)) => Some(&left * &right),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    };

    for (pos, ((tie_idx, input_idx), rotated_idx)) in tie_indices
        .iter()
        .copied()
        .zip(input_indices.iter().copied())
        .zip(rotated_indices.iter().copied())
        .enumerate()
    {
        let tie_col = tie_table.tracked_col_oracle_by_ind(tie_idx);
        let input_col = input_table.tracked_col_oracle_by_ind(input_idx);
        let rotated_col = rotated_table.tracked_col_oracle_by_ind(rotated_idx);
        let col_name = input_col
            .field_ref()
            .expect("Expected field ref for Sort sign input")
            .name()
            .to_string();
        let col_name = normalize_sort_name(&col_name);
        let is_asc = sort_is_asc(sort_specs, &col_name);
        let sign = match sort_config {
            SortConfig::Uniform(config) => sign_for_column(config.asc, config.strict),
            SortConfig::PerColumn(config) => {
                let strict_for_col = config.strict && pos + 1 == input_indices.len();
                sign_for_column(is_asc, strict_for_col)
            }
        };

        let input_field = input_col
            .field_ref()
            .expect("Expected field ref for Sort sign input");
        let (diff_oracle, diff_field) = match difference_sign_type(input_field.data_type()) {
            Some(sign_type) => {
                let input_oracle = input_col.data_tracked_oracle();
                let rotated_oracle = rotated_col.data_tracked_oracle();
                let diff_oracle = if is_asc {
                    &rotated_oracle - &input_oracle
                } else {
                    &input_oracle - &rotated_oracle
                };
                (
                    diff_oracle,
                    Field::new(input_field.name(), sign_type, false),
                )
            }
            None => {
                let diff_col = diff_table
                    .and_then(|table| {
                        table
                            .data_tracked_oracles_indices()
                            .into_iter()
                            .map(|idx| table.tracked_col_oracle_by_ind(idx))
                            .find(|col| {
                                col.field_ref().is_some_and(|field| {
                                    normalize_sort_name(field.name()) == col_name
                                })
                            })
                    })
                    .expect("Expected a sign-only diff column for Sort key");
                let diff_field = diff_col
                    .field_ref()
                    .expect("Expected field ref for Sort diff input")
                    .as_ref()
                    .clone();
                (
                    diff_col
                        .data_tracked_oracle()
                        .sub_scalar_oracle(B::F::one()),
                    diff_field,
                )
            }
        };

        let tie_oracle = tie_col.data_tracked_oracle();
        let one_oracle = TrackedOracle::new(
            Either::Right(B::F::one()),
            tie_oracle.tracker(),
            tie_oracle.log_size(),
        );
        let masked_diff = match sign {
            sign::Sign::Positive | sign::Sign::Negative => {
                &(&diff_oracle * &tie_oracle) + &(&(&one_oracle - &tie_oracle) * &one_oracle)
            }
            _ => &diff_oracle * &tie_oracle,
        };
        data_cols.insert(Arc::new(diff_field), masked_diff);
    }

    if let Some(activator) = combined_activator {
        data_cols.insert(ACTIVATOR_FIELD.clone(), activator);
    }

    let sign_input = TrackedTableOracle::new(None, data_cols, input_table.log_size());
    let mut sign_payload = match virtualized_ir.payload_for_node(&sign_gadget.id()) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    sign_payload.insert(sign::INPUT_LABEL.to_string(), sign_input);
    virtualized_ir.set_payload_for_node(
        sign_gadget.id(),
        Some(PayloadStructure::GadgetPayload(sign_payload)),
    );
    Ok(())
}

fn populate_neq_payloads_prover<B: SnarkBackend>(
    neq_gadget: &Arc<Node<B>>,
    sort_specs: &[(String, bool, bool)],
    tie_table: &TrackedTable<B>,
    input_table: &TrackedTable<B>,
    rotated_table: &TrackedTable<B>,
    virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let tie_indices = tie_table.data_tracked_polys_indices();
    let input_indices = ordered_data_indices_prover(input_table, sort_specs);
    let rotated_indices = ordered_data_indices_prover(rotated_table, sort_specs);
    debug_assert_eq!(
        tie_indices.len(),
        input_indices.len(),
        "Sort neq gadget expects one tie indicator per data column."
    );
    debug_assert_eq!(
        input_indices.len(),
        rotated_indices.len(),
        "Sort neq gadget expects matching input and rotated column counts."
    );
    if input_indices.len() < 2 {
        let Some(sample_col) = input_table
            .data_tracked_polys_indices()
            .first()
            .copied()
            .and_then(|idx| input_table.tracked_col_by_ind(idx).field_ref())
        else {
            return Ok(());
        };
        let log_size = input_table.log_size();
        let tracker = tie_table
            .tracked_col_by_ind(tie_indices[0])
            .data_tracked_poly()
            .tracker();
        let zero_poly = TrackedPoly::new(Either::Right(B::F::zero()), log_size, tracker);
        let mut left_cols = IndexMap::new();
        let mut right_cols = IndexMap::new();
        left_cols.insert(sample_col.clone(), zero_poly.clone());
        right_cols.insert(sample_col, zero_poly.clone());
        left_cols.insert(ACTIVATOR_FIELD.clone(), zero_poly.clone());
        right_cols.insert(ACTIVATOR_FIELD.clone(), zero_poly);
        let left_table = TrackedTable::new(None, left_cols, log_size);
        let right_table = TrackedTable::new(None, right_cols, log_size);
        let mut neq_payload = match virtualized_ir.payload_for_node(&neq_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        neq_payload.insert(neq::LEFT_LABEL.to_string(), left_table);
        neq_payload.insert(neq::RIGHT_LABEL.to_string(), right_table);
        virtualized_ir.set_payload_for_node(
            neq_gadget.id(),
            Some(PayloadStructure::GadgetPayload(neq_payload)),
        );
        return Ok(());
    }

    let input_activator = input_table.activator_tracked_poly();
    let rotated_activator = rotated_table.activator_tracked_poly();
    let combined_activator = match (input_activator, rotated_activator) {
        (Some(left), Some(right)) => Some(&left * &right),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    };

    let one_poly = {
        let tie_col = tie_table.tracked_col_by_ind(tie_indices[0]);
        TrackedPoly::new(
            Either::Right(B::F::one()),
            tie_col.data_tracked_poly().log_size(),
            tie_col.data_tracked_poly().tracker(),
        )
    };
    let mut no_tie_break = one_poly.clone();
    let mut left_cols = IndexMap::new();
    let mut right_cols = IndexMap::new();
    for (idx, ((tie_idx, tie_next_idx), (input_idx, rotated_idx))) in tie_indices
        .iter()
        .copied()
        .zip(tie_indices.iter().copied().skip(1))
        .zip(
            input_indices
                .iter()
                .copied()
                .zip(rotated_indices.iter().copied()),
        )
        .enumerate()
    {
        if idx + 1 == input_indices.len() {
            break;
        }
        let tie_col = tie_table.tracked_col_by_ind(tie_idx);
        let tie_next_col = tie_table.tracked_col_by_ind(tie_next_idx);
        let one_poly = TrackedPoly::new(
            Either::Right(B::F::one()),
            tie_next_col.data_tracked_poly().log_size(),
            tie_next_col.data_tracked_poly().tracker(),
        );
        let tie_break =
            &tie_col.data_tracked_poly() * &(&one_poly - &tie_next_col.data_tracked_poly());
        no_tie_break = &no_tie_break * &(&one_poly - &tie_break);
        let input_col = input_table.tracked_col_by_ind(input_idx);
        let rotated_col = rotated_table.tracked_col_by_ind(rotated_idx);
        let data_field = input_col
            .field_ref()
            .expect("Expected field ref for Sort neq input");
        left_cols.insert(
            data_field.clone(),
            &rotated_col.data_tracked_poly() * &tie_break,
        );
        right_cols.insert(data_field, &input_col.data_tracked_poly() * &tie_break);
    }
    let any_tie_break = &one_poly - &no_tie_break;
    if let Some(activator) = combined_activator {
        let gated = &activator * &any_tie_break;
        left_cols.insert(ACTIVATOR_FIELD.clone(), gated.clone());
        right_cols.insert(ACTIVATOR_FIELD.clone(), gated);
    }
    let left_table = TrackedTable::new(None, left_cols, input_table.log_size());
    let right_table = TrackedTable::new(None, right_cols, input_table.log_size());

    let mut neq_payload = match virtualized_ir.payload_for_node(&neq_gadget.id()) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    neq_payload.insert(neq::LEFT_LABEL.to_string(), left_table);
    neq_payload.insert(neq::RIGHT_LABEL.to_string(), right_table);
    virtualized_ir.set_payload_for_node(
        neq_gadget.id(),
        Some(PayloadStructure::GadgetPayload(neq_payload)),
    );
    Ok(())
}

fn populate_neq_payloads_verifier<B: SnarkBackend>(
    neq_gadget: &Arc<Node<B>>,
    sort_specs: &[(String, bool, bool)],
    tie_table: &TrackedTableOracle<B>,
    input_table: &TrackedTableOracle<B>,
    rotated_table: &TrackedTableOracle<B>,
    virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let tie_indices = tie_table.data_tracked_oracles_indices();
    let input_indices = ordered_data_indices_verifier(input_table, sort_specs);
    let rotated_indices = ordered_data_indices_verifier(rotated_table, sort_specs);
    debug_assert_eq!(
        tie_indices.len(),
        input_indices.len(),
        "Sort neq gadget expects one tie indicator per data column."
    );
    debug_assert_eq!(
        input_indices.len(),
        rotated_indices.len(),
        "Sort neq gadget expects matching input and rotated column counts."
    );
    if input_indices.len() < 2 {
        let Some(sample_col) = input_table
            .data_tracked_oracles_indices()
            .first()
            .copied()
            .and_then(|idx| input_table.tracked_col_oracle_by_ind(idx).field_ref())
        else {
            return Ok(());
        };
        let log_size = input_table.log_size();
        let tracker = tie_table
            .tracked_col_oracle_by_ind(tie_indices[0])
            .data_tracked_oracle()
            .tracker();
        let zero_oracle = TrackedOracle::new(Either::Right(B::F::zero()), tracker, log_size);
        let mut left_cols = IndexMap::new();
        let mut right_cols = IndexMap::new();
        left_cols.insert(sample_col.clone(), zero_oracle.clone());
        right_cols.insert(sample_col, zero_oracle.clone());
        left_cols.insert(ACTIVATOR_FIELD.clone(), zero_oracle.clone());
        right_cols.insert(ACTIVATOR_FIELD.clone(), zero_oracle);
        let left_table = TrackedTableOracle::new(None, left_cols, log_size);
        let right_table = TrackedTableOracle::new(None, right_cols, log_size);
        let mut neq_payload = match virtualized_ir.payload_for_node(&neq_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        neq_payload.insert(neq::LEFT_LABEL.to_string(), left_table);
        neq_payload.insert(neq::RIGHT_LABEL.to_string(), right_table);
        virtualized_ir.set_payload_for_node(
            neq_gadget.id(),
            Some(PayloadStructure::GadgetPayload(neq_payload)),
        );
        return Ok(());
    }

    let input_activator = input_table.activator_tracked_poly();
    let rotated_activator = rotated_table.activator_tracked_poly();
    let combined_activator = match (input_activator, rotated_activator) {
        (Some(left), Some(right)) => Some(&left * &right),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    };

    let one_oracle = TrackedOracle::new(
        Either::Right(B::F::one()),
        tie_table
            .tracked_col_oracle_by_ind(tie_indices[0])
            .data_tracked_oracle()
            .tracker(),
        tie_table.log_size(),
    );
    let mut no_tie_break = one_oracle.clone();
    let mut left_cols = IndexMap::new();
    let mut right_cols = IndexMap::new();
    for (idx, ((tie_idx, tie_next_idx), (input_idx, rotated_idx))) in tie_indices
        .iter()
        .copied()
        .zip(tie_indices.iter().copied().skip(1))
        .zip(
            input_indices
                .iter()
                .copied()
                .zip(rotated_indices.iter().copied()),
        )
        .enumerate()
    {
        if idx + 1 == input_indices.len() {
            break;
        }
        let tie_col = tie_table.tracked_col_oracle_by_ind(tie_idx);
        let tie_next_col = tie_table.tracked_col_oracle_by_ind(tie_next_idx);
        let one_oracle = TrackedOracle::new(
            Either::Right(B::F::one()),
            tie_next_col.data_tracked_oracle().tracker(),
            tie_next_col.data_tracked_oracle().log_size(),
        );
        let tie_break =
            &tie_col.data_tracked_oracle() * &(&one_oracle - &tie_next_col.data_tracked_oracle());
        no_tie_break = &no_tie_break * &(&one_oracle - &tie_break);
        let input_col = input_table.tracked_col_oracle_by_ind(input_idx);
        let rotated_col = rotated_table.tracked_col_oracle_by_ind(rotated_idx);
        let data_field = input_col
            .field_ref()
            .expect("Expected field ref for Sort neq input");
        left_cols.insert(
            data_field.clone(),
            &rotated_col.data_tracked_oracle() * &tie_break,
        );
        right_cols.insert(data_field, &input_col.data_tracked_oracle() * &tie_break);
    }
    let any_tie_break = &one_oracle - &no_tie_break;
    if let Some(activator) = combined_activator {
        let gated = &activator * &any_tie_break;
        left_cols.insert(ACTIVATOR_FIELD.clone(), gated.clone());
        right_cols.insert(ACTIVATOR_FIELD.clone(), gated);
    }
    let left_table = TrackedTableOracle::new(None, left_cols, input_table.log_size());
    let right_table = TrackedTableOracle::new(None, right_cols, input_table.log_size());

    let mut neq_payload = match virtualized_ir.payload_for_node(&neq_gadget.id()) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    neq_payload.insert(neq::LEFT_LABEL.to_string(), left_table);
    neq_payload.insert(neq::RIGHT_LABEL.to_string(), right_table);
    virtualized_ir.set_payload_for_node(
        neq_gadget.id(),
        Some(PayloadStructure::GadgetPayload(neq_payload)),
    );
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
        verifier.add_mv_zerocheck_claim(zero_oracle.id());
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

    let tie_indices = tie_table.data_tracked_polys_indices();
    let input_indices = non_row_id_data_indices_prover(&input_table);
    let rotated_indices = non_row_id_data_indices_prover(&rotated_table);
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

    // Enforce first_tie * tie_i * input_activator * (input_{i-1} - rotated_{i-1}) = 0 for i > 0.
    // first_tie masks the wrap-around row (last -> first), and input activator gates inactive rows.
    let first_tie_poly = tie_table
        .tracked_col_by_ind(tie_indices[0])
        .data_tracked_poly();
    let input_activator = input_table.activator_tracked_poly();
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

        let tie_poly = &tie_col.data_tracked_poly() * &first_tie_poly;
        let diff_poly = &input_col.data_tracked_poly() - &rotated_col.data_tracked_poly();
        let gated_diff_poly = match input_activator.as_ref() {
            Some(activator) => &diff_poly * activator,
            None => diff_poly,
        };
        let zero_poly = &tie_poly * &gated_diff_poly;
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

    let tie_indices = tie_table.data_tracked_oracles_indices();
    let input_indices = non_row_id_data_indices_verifier(&input_table);
    let rotated_indices = non_row_id_data_indices_verifier(&rotated_table);
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

    // Enforce first_tie * tie_i * input_activator * (input_{i-1} - rotated_{i-1}) = 0 for i > 0.
    // first_tie masks the wrap-around row (last -> first), and input activator gates inactive rows.
    let first_tie_oracle = tie_table
        .tracked_col_oracle_by_ind(tie_indices[0])
        .data_tracked_oracle();
    let input_activator = input_table.activator_tracked_poly();
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

        let tie_oracle = &tie_col.data_tracked_oracle() * &first_tie_oracle;
        let diff_oracle = &input_col.data_tracked_oracle() - &rotated_col.data_tracked_oracle();
        let gated_diff_oracle = match input_activator.as_ref() {
            Some(activator) => &diff_oracle * activator,
            None => diff_oracle,
        };
        let zero_oracle = &tie_oracle * &gated_diff_oracle;
        verifier.add_mv_zerocheck_claim(zero_oracle.id());
    }
    Ok(())
}

/// Puts the public `tie_0 = 1 - eq(x, 1^n)` in front of the committed ties
/// `tie_1..` (paper PIOP 7, step 2: the verifier sets ties_0). A supplied
/// `tie_0` is dropped: a committed one would let the prover switch every
/// comparison off.
fn prepend_first_tie_indicator_prover<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    table: Option<&TrackedTable<B>>,
    num_vars: usize,
) -> TrackedTable<B> {
    let one_tracked_poly = prover.track_mat_mv_cnst_poly(num_vars, B::F::one());
    let tracker = one_tracked_poly.tracker();
    let tracked_last_eq_poly = if num_vars == 0 {
        // For nv=0, eq_x_r is the constant 1; track it as a constant poly.
        prover.track_mat_mv_cnst_poly(num_vars, B::F::one())
    } else {
        let last_eq_poly =
            build_eq_x_r(&vec![B::F::one(); num_vars]).expect("build_eq_x_r should succeed");
        let last_eq_id = tracker
            .borrow_mut()
            .track_mat_mv_poly(last_eq_poly.as_ref().clone());
        TrackedPoly::new(Either::Left(last_eq_id), num_vars, tracker)
    };
    let first_tie_poly = &one_tracked_poly - &tracked_last_eq_poly;

    let first_tie_field = Arc::new(Field::new(FIRST_TIE_LABEL, DataType::Boolean, false));
    let mut tracked_polys = IndexMap::new();
    tracked_polys.insert(first_tie_field.clone(), first_tie_poly);
    for (field, poly) in table.iter().flat_map(|table| table.tracked_polys_iter()) {
        if field.name() != FIRST_TIE_LABEL {
            tracked_polys.insert(field.clone(), poly.clone());
        }
    }

    let schema = table.and_then(|table| table.schema_ref()).map(|schema| {
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
    TrackedTable::new(schema, tracked_polys, num_vars)
}

fn prepend_first_tie_indicator_verifier<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    table: Option<&TrackedTableOracle<B>>,
    num_vars: usize,
) -> TrackedTableOracle<B> {
    let one_tracked_oracle = verifier.track_mat_mv_cnst_oracle(num_vars, B::F::one());
    let tracker = one_tracked_oracle.tracker();
    let tracked_last_eq_oracle = if num_vars == 0 {
        // For nv=0, eq_x_r is the constant 1; track it as a constant oracle.
        verifier.track_mat_mv_cnst_oracle(num_vars, B::F::one())
    } else {
        let last_eq_sparse = build_sparse_eq_x_r(&vec![B::F::one(); num_vars])
            .expect("build_sparse_eq_x_r should succeed");
        let last_eq_oracle = Oracle::new_multivariate(num_vars, move |point: Vec<B::F>| {
            Ok(last_eq_sparse.evaluate(&point))
        });
        let last_eq_id = tracker.borrow_mut().track_base_oracle(last_eq_oracle);
        TrackedOracle::new(Either::Left(last_eq_id), tracker, num_vars)
    };
    let first_tie_oracle = &one_tracked_oracle - &tracked_last_eq_oracle;

    let first_tie_field = Arc::new(Field::new(FIRST_TIE_LABEL, DataType::Boolean, false));
    let mut tracked_oracles = IndexMap::new();
    tracked_oracles.insert(first_tie_field.clone(), first_tie_oracle);
    for (field, oracle) in table.iter().flat_map(|table| table.tracked_oracles_iter()) {
        if field.name() != FIRST_TIE_LABEL {
            tracked_oracles.insert(field.clone(), oracle.clone());
        }
    }

    let schema = table.and_then(|table| table.schema_ref()).map(|schema| {
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
    TrackedTableOracle::new(schema, tracked_oracles, num_vars)
}

fn pad_df_to_power_of_two(
    df: datafusion::prelude::DataFrame,
) -> datafusion_common::Result<datafusion::prelude::DataFrame> {
    let schema_ref = df.schema();
    let arrow_schema: Schema = <DFSchema as AsRef<Schema>>::as_ref(schema_ref).clone();
    let arrow_schema = Schema::new_with_metadata(
        arrow_schema
            .fields()
            .iter()
            .map(|field| {
                Field::new(field.name(), field.data_type().clone(), true)
                    .with_metadata(field.metadata().clone())
            })
            .collect::<Vec<_>>(),
        arrow_schema.metadata().clone(),
    );
    let batches = crate::session::block_on(df.collect())?;
    let (batches, _row_count) = pad_batches_to_power_of_two(&arrow_schema, batches)?;
    if batches.is_empty() {
        return Err(DataFusionError::Execution(
            "contig sort padding produced empty batches".to_string(),
        ));
    }
    let mem_table = MemTable::try_new(Arc::new(arrow_schema), vec![batches])
        .map_err(|e| DataFusionError::Execution(e.to_string()))?;
    let ctx = session_context();
    let padded_df = ctx
        .read_table(Arc::new(mem_table))
        .map_err(|e| DataFusionError::Execution(e.to_string()))?;
    Ok(padded_df)
}

fn pad_batches_to_power_of_two(
    schema: &Schema,
    batches: Vec<RecordBatch>,
) -> datafusion_common::Result<(Vec<RecordBatch>, usize)> {
    let row_count: usize = batches.iter().map(|b| b.num_rows()).sum();
    let target = if row_count == 0 {
        2
    } else {
        row_count.next_power_of_two()
    };
    let pad = target - row_count;
    if pad == 0 {
        return Ok((batches, row_count));
    }

    let schema_ref = Arc::new(schema.clone());
    let combined = if batches.is_empty() {
        None
    } else {
        let batch_refs: Vec<&RecordBatch> = batches.iter().collect();
        Some(concat_batches(&schema_ref, batch_refs)?)
    };

    let mut output_arrays = Vec::with_capacity(schema_ref.fields().len());
    for (idx, field) in schema_ref.fields().iter().enumerate() {
        let padded = if field.name() == arithmetic::ACTIVATOR_COL_NAME {
            let base = combined
                .as_ref()
                .map(|batch| batch.column(idx).clone())
                .unwrap_or_else(|| Arc::new(BooleanArray::from(Vec::<bool>::new())) as ArrayRef);
            let pad_arr: ArrayRef = Arc::new(BooleanArray::from(vec![false; pad]));
            concat(&[base.as_ref(), pad_arr.as_ref()])?
        } else if field.data_type() == &DataType::Boolean {
            // Non-system boolean columns are false on padded rows to avoid
            // introducing accidental truthy constraints in downstream gadgets.
            let base = combined
                .as_ref()
                .map(|batch| batch.column(idx).clone())
                .unwrap_or_else(|| Arc::new(BooleanArray::from(Vec::<bool>::new())) as ArrayRef);
            let pad_arr: ArrayRef = Arc::new(BooleanArray::from(vec![false; pad]));
            concat(&[base.as_ref(), pad_arr.as_ref()])?
        } else if field.name() == ROW_ID_COL_NAME {
            // Continue the row ids across padding so that an ordering by row id
            // stays deterministic after materialization.
            let base = combined
                .as_ref()
                .map(|batch| batch.column(idx).clone())
                .unwrap_or_else(|| Arc::new(Int64Array::from(Vec::<i64>::new())) as ArrayRef);
            let start = combined
                .as_ref()
                .and_then(|batch| {
                    ScalarValue::try_from_array(batch.column(idx).as_ref(), row_count - 1).ok()
                })
                .and_then(|val| match val {
                    ScalarValue::Int64(Some(v)) => Some(v + 1),
                    ScalarValue::UInt64(Some(v)) => i64::try_from(v).ok().map(|v| v + 1),
                    _ => None,
                })
                .unwrap_or(0);
            let pad_vals: Vec<i64> = (0..pad as i64).map(|offset| start + offset).collect();
            let pad_arr: ArrayRef = Arc::new(Int64Array::from(pad_vals));
            concat(&[base.as_ref(), pad_arr.as_ref()])?
        } else if let Some(batch) = combined.as_ref() {
            let base = batch.column(idx).clone();
            // Repeat the last value on padded rows, as the gadgets downstream expect.
            let last = ScalarValue::try_from_array(base.as_ref(), row_count - 1)?;
            let pad_arr = last.to_array_of_size(pad)?;
            concat(&[base.as_ref(), pad_arr.as_ref()])?
        } else {
            let null = ScalarValue::try_new_null(field.data_type())?;
            null.to_array_of_size(pad)?
        };
        output_arrays.push(padded);
    }

    let out_batch = RecordBatch::try_new(schema_ref, output_arrays)?;
    Ok((vec![out_batch], target))
}

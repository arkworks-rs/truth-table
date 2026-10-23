use crate::session::session_context;
use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_FIELD, ROW_ID_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_ff::One;
use ark_piop::SnarkBackend;
use ark_piop::errors::{SnarkError, SnarkResult};
use ark_piop::prover::structs::polynomial::get_or_insert_shift_poly;
use ark_piop::verifier::errors::VerifierError;
use ark_piop::verifier::structs::oracle::get_or_insert_shift_oracle;
use ark_piop::{
    prover::ArgProver, prover::structs::polynomial::TrackedPoly, verifier::ArgVerifier,
    verifier::structs::oracle::TrackedOracle,
};
use datafusion::arrow::{
    array::{ArrayRef, BooleanArray, Int64Array},
    compute::{concat, concat_batches},
    datatypes::{DataType, Field, FieldRef, IntervalUnit, Schema},
    record_batch::RecordBatch,
};
use datafusion::datasource::MemTable;
use datafusion_common::{DFSchema, DataFusionError, ScalarValue};
use either::Either;
use indexmap::IndexMap;

use crate::irs::nodes::utils::{field_to_usize, perm, sign};
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
mod distinct;
mod hints;
#[cfg(test)]
pub(crate) mod tests;

pub const TABLE_LABEL: &str = "__input__";
pub const ROTATED_INPUT_LABEL: &str = "__rotated_input__";
pub const TIE_INDICATOR_LABEL: &str = "__tie_indicator__";
pub const DIFF_INPUT_LABEL: &str = "__diff_input__";
/// A zero-variable table holding `s`, the number of active rows. The input's
/// activator must be `C_{µ,s}`: the check covers its first `s` rows.
pub const ACTIVE_ROWS_LABEL: &str = "__active_rows__";

/// The column of the [`ACTIVE_ROWS_LABEL`] table.
pub fn active_rows_field() -> FieldRef {
    Arc::new(Field::new("active_rows", DataType::UInt64, false))
}
const FIRST_TIE_LABEL: &str = "tie_0";

pub(crate) use distinct::sort_distinct;
use distinct::{DistinctLayout, distinct_view, distinct_view_fields};

/// The committed limbs of the hash slots a distinct sort compares.
pub const LIMBS_LABEL: &str = "__limbs__";

pub enum SortConfig {
    /// Strictly ascending in some order: the rows are distinct. Hashed
    /// columns are compared on their hash limbs ([`distinct`]).
    Distinct,
    PerColumn(PerColumnConfig),
}

pub struct PerColumnConfig {
    pub sort_specs: Vec<(String, bool, bool)>,
    pub strict: bool,
}

/// Enforces that a table is sorted according to its sort config.
pub struct GadgetNode<B: SnarkBackend> {
    perm: Arc<Node<B>>,
    bool_gadget: Arc<Node<B>>,
    sign_gadget: Arc<Node<B>>,
    sort_config: SortConfig,
    strip_row_id: bool,
    /// The distinct mode's layout, read from the input table.
    distinct_layout: std::sync::Mutex<Option<DistinctLayout>>,
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
            self.perm.clone(),
            self.bool_gadget.clone(),
            self.sign_gadget.clone(),
        ]
    }
}

/// The number of active rows `s` the caller passes under
/// [`ACTIVE_ROWS_LABEL`]: the input's activator is `C_{µ,s}`.
fn active_rows_prover<B: SnarkBackend>(table: &TrackedTable<B>) -> SnarkResult<usize> {
    let count = table
        .all_tracked_cols()
        .first()
        .map(|col| col.data_tracked_poly())
        .filter(|poly| poly.log_size() == 0);
    match count {
        Some(poly) => field_to_usize(poly.evaluations()[0], "the sorted table's active rows"),
        None => Err(not_a_count()),
    }
}

fn active_rows_verifier<B: SnarkBackend>(table: &TrackedTableOracle<B>) -> SnarkResult<usize> {
    let count = table
        .all_tracked_col_oracles()
        .first()
        .map(|col| col.data_tracked_oracle())
        .filter(|oracle| oracle.log_size() == 0)
        .and_then(|oracle| oracle.as_constant());
    match count {
        Some(value) => field_to_usize(value, "the sorted table's active rows"),
        None => Err(not_a_count()),
    }
}

fn not_a_count() -> SnarkError {
    SnarkError::VerifierError(VerifierError::VerifierCheckFailed(
        "the sort check's active-row count is not a scalar".to_string(),
    ))
}

/// The shift tables of paper PIOP 7: `(C_{µ,s-1}, [idx + 1, d'])` and
/// `(C_{µ,s} - eq(X, 0^µ), [idx, d])`. Both hold `s - 1` rows and `j ↦ j+1`
/// pairs them, so their multiset equality forces `d'[j] = d[j+1]` for
/// `j < s - 1`; rows of `d'` from `s - 1` on are never read. All three
/// polynomials besides `d` and `d'` are public.
fn shift_tables_prover<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    columns: &[(TrackedPoly<B>, TrackedPoly<B>)],
    mask: &TrackedPoly<B>,
    s: usize,
) -> SnarkResult<(TrackedTable<B>, TrackedTable<B>)> {
    let log_size = mask.log_size();
    let index = get_or_insert_shift_poly(prover, log_size, 0, true);
    let shifted_activator =
        prover.get_or_build_contig_skipped_one_poly(log_size, s.saturating_sub(1), 1)?;
    let mut left = IndexMap::from([(position_field(), index.add_scalar_poly(B::F::one()))]);
    let mut right = IndexMap::from([(position_field(), index)]);
    for (k, (data, data_rotated)) in columns.iter().enumerate() {
        left.insert(key_field(k), data_rotated.clone());
        right.insert(key_field(k), data.clone());
    }
    left.insert(ACTIVATOR_FIELD.clone(), mask.clone());
    right.insert(ACTIVATOR_FIELD.clone(), shifted_activator);
    Ok((
        TrackedTable::new(None, left, log_size),
        TrackedTable::new(None, right, log_size),
    ))
}

fn shift_tables_verifier<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    columns: &[(TrackedOracle<B>, TrackedOracle<B>)],
    mask: &TrackedOracle<B>,
    s: usize,
) -> SnarkResult<(TrackedTableOracle<B>, TrackedTableOracle<B>)> {
    let log_size = mask.log_size();
    let index = get_or_insert_shift_oracle(verifier, log_size, 0, true);
    let shifted_activator =
        verifier.get_or_build_contig_skipped_one_poly(log_size, s.saturating_sub(1), 1)?;
    let mut left = IndexMap::from([(position_field(), index.add_scalar_oracle(B::F::one()))]);
    let mut right = IndexMap::from([(position_field(), index)]);
    for (k, (data, data_rotated)) in columns.iter().enumerate() {
        left.insert(key_field(k), data_rotated.clone());
        right.insert(key_field(k), data.clone());
    }
    left.insert(ACTIVATOR_FIELD.clone(), mask.clone());
    right.insert(ACTIVATOR_FIELD.clone(), shifted_activator);
    Ok((
        TrackedTableOracle::new(None, left, log_size),
        TrackedTableOracle::new(None, right, log_size),
    ))
}

fn position_field() -> FieldRef {
    Arc::new(Field::new("position", DataType::UInt64, false))
}

fn key_field(k: usize) -> FieldRef {
    Arc::new(Field::new(format!("key_{k}"), DataType::UInt64, false))
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
    let planning_error = |e: DataFusionError| SnarkError::Artifact(format!("sort planning: {e}"));
    // The distinct mode sorts its view: the order-preserving columns and the
    // hash limbs.
    let layout = match node.sort_config {
        SortConfig::Distinct => {
            let fields: Vec<Field> = input_hint
                .data_frame()
                .schema()
                .fields()
                .iter()
                .map(|field| field.as_ref().clone())
                .collect();
            let layout = DistinctLayout::new::<B::F>(&fields).map_err(planning_error)?;
            Some((layout, fields))
        }
        SortConfig::PerColumn(_) => None,
    };
    let input_hint = match &layout {
        Some((layout, fields)) if is_verifier => crate::irs::nodes::hints::HintDF::new_virtual(
            crate::irs::nodes::hints::schema_only_df(distinct_view_fields(fields, layout)),
        ),
        Some(_) => crate::irs::nodes::hints::HintDF::new_virtual(
            distinct_view::<B::F>(input_hint.data_frame().clone()).map_err(planning_error)?,
        ),
        None => input_hint,
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
    if let Some((layout, _)) = &layout
        && !layout.slots.is_empty()
    {
        let limb_fields: Vec<Field> = layout.limb_fields().cloned().collect();
        let limbs_hint = if is_verifier {
            build_empty_hint_df_with_fields(limb_fields, true)
        } else {
            let columns = limb_fields
                .iter()
                .map(|field| datafusion::prelude::col(field.name()))
                .collect::<Vec<_>>();
            crate::irs::nodes::hints::HintDF::new_materialized(
                sorted_input_hint
                    .data_frame()
                    .clone()
                    .select(columns)
                    .map_err(planning_error)?,
            )
        };
        gadget_payload.insert(LIMBS_LABEL.to_string(), limbs_hint);
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
        let Some(input) = payload.get(TABLE_LABEL).cloned() else {
            return Ok(());
        };
        let input = &self.distinct_view_prover(input, &mut payload)?;
        let rotated = payload
            .get(ROTATED_INPUT_LABEL)
            .unwrap_or_else(|| panic!("Expected rotated input payload for Sort gadget"));
        let count = payload
            .get(ACTIVE_ROWS_LABEL)
            .unwrap_or_else(|| panic!("Expected active-row count for Sort gadget"));
        let s = active_rows_prover(count)?;
        let mask = prover.get_or_build_contig_one_poly(input.log_size(), s.saturating_sub(1))?;
        let rotated = with_activator_prover(rotated, mask.clone());
        let sort_specs = sort_specs_for_table_prover(&self.sort_config, input);

        let shift_tables = shift_tables_prover(
            prover,
            &sort_columns_prover(input, &rotated, &sort_specs),
            &mask,
            s,
        )?;
        let mut perm_payload = match virtualized_ir.payload_for_node(&self.perm.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        perm_payload.insert(perm::LEFT_LABEL.to_string(), shift_tables.0);
        perm_payload.insert(perm::RIGHT_LABEL.to_string(), shift_tables.1);
        virtualized_ir.set_payload_for_node(
            self.perm.id(),
            Some(PayloadStructure::GadgetPayload(perm_payload)),
        );

        let committed_ties = payload.get(TIE_INDICATOR_LABEL);
        let ties = prepend_first_tie_indicator_prover(committed_ties, mask);
        // The committed ties must be Boolean. A single-key sort has none; the
        // Bool gadget then checks the public `tie_0`, which always passes.
        let bool_table = committed_ties.cloned().unwrap_or_else(|| ties.clone());
        let mut bool_payload = match virtualized_ir.payload_for_node(&self.bool_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        bool_payload.insert(
            crate::irs::nodes::utils::bool::TABLE_LABEL.to_string(),
            bool_table,
        );
        virtualized_ir.set_payload_for_node(
            self.bool_gadget.id(),
            Some(PayloadStructure::GadgetPayload(bool_payload)),
        );
        populate_sign_payloads_prover(
            &self.sign_gadget,
            &self.sort_config,
            &sort_specs,
            payload.get(DIFF_INPUT_LABEL),
            &ties,
            input,
            &rotated,
            virtualized_ir,
        )?;
        payload.insert(TIE_INDICATOR_LABEL.to_string(), ties);
        payload.insert(ROTATED_INPUT_LABEL.to_string(), rotated);
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
        let Some(input) = payload.get(TABLE_LABEL).cloned() else {
            return Ok(());
        };
        let input = &self.distinct_view_verifier(input, &mut payload)?;
        let rotated = payload
            .get(ROTATED_INPUT_LABEL)
            .unwrap_or_else(|| panic!("Expected rotated input payload for Sort gadget"));
        let count = payload
            .get(ACTIVE_ROWS_LABEL)
            .unwrap_or_else(|| panic!("Expected active-row count for Sort gadget"));
        let s = active_rows_verifier(count)?;
        let mask = verifier.get_or_build_contig_one_poly(input.log_size(), s.saturating_sub(1))?;
        let rotated = with_activator_verifier(rotated, mask.clone());
        let sort_specs = sort_specs_for_table_verifier(&self.sort_config, input);

        let shift_tables = shift_tables_verifier(
            verifier,
            &sort_columns_verifier(input, &rotated, &sort_specs),
            &mask,
            s,
        )?;
        let mut perm_payload = match virtualized_ir.payload_for_node(&self.perm.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        perm_payload.insert(perm::LEFT_LABEL.to_string(), shift_tables.0);
        perm_payload.insert(perm::RIGHT_LABEL.to_string(), shift_tables.1);
        virtualized_ir.set_payload_for_node(
            self.perm.id(),
            Some(PayloadStructure::GadgetPayload(perm_payload)),
        );

        let committed_ties = payload.get(TIE_INDICATOR_LABEL);
        let ties = prepend_first_tie_indicator_verifier(committed_ties, mask);
        // The committed ties must be Boolean. A single-key sort has none; the
        // Bool gadget then checks the public `tie_0`, which always passes.
        let bool_table = committed_ties.cloned().unwrap_or_else(|| ties.clone());
        let mut bool_payload = match virtualized_ir.payload_for_node(&self.bool_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        bool_payload.insert(
            crate::irs::nodes::utils::bool::TABLE_LABEL.to_string(),
            bool_table,
        );
        virtualized_ir.set_payload_for_node(
            self.bool_gadget.id(),
            Some(PayloadStructure::GadgetPayload(bool_payload)),
        );
        populate_sign_payloads_verifier(
            &self.sign_gadget,
            &self.sort_config,
            &sort_specs,
            payload.get(DIFF_INPUT_LABEL),
            &ties,
            input,
            &rotated,
            virtualized_ir,
        )?;
        payload.insert(TIE_INDICATOR_LABEL.to_string(), ties);
        payload.insert(ROTATED_INPUT_LABEL.to_string(), rotated);
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
        // Paper PIOP 7 steps 3(c), tie monotonicity, and 3(d), `d_i = d'_i` on
        // `ties_i`, are not checked: the checker is sound without them (paper
        // Lemma "checker soundness"), given step 3(e) per column.
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let (Some(ties), Some(input), Some(rotated)) = (
            payload.get(TIE_INDICATOR_LABEL),
            payload.get(TABLE_LABEL),
            payload.get(ROTATED_INPUT_LABEL),
        ) else {
            return Ok(());
        };
        if let Some(check) = payload.get(LIMBS_LABEL) {
            self.prove_limbs(prover, check)?;
        }
        let sort_specs = sort_specs_for_table_prover(&self.sort_config, input);
        let columns = sort_columns_prover(input, rotated, &sort_specs);
        let ties: Vec<_> = ties
            .data_tracked_polys_indices()
            .into_iter()
            .map(|idx| ties.tracked_col_by_ind(idx).data_tracked_poly())
            .collect();
        let mask = rotated
            .activator_tracked_poly()
            .expect("the rotated table carries the mask C_{µ,s-1}");
        if columns.len() < 2 {
            return Ok(());
        }
        let c = prover.get_and_append_challenge(b"sort_tie_break")?;
        for (k, (data, data_rotated)) in columns.iter().enumerate().take(columns.len() - 1) {
            let breaks = &(&ties[k]
                * &ties[k + 1]
                    .mul_scalar_poly(-B::F::one())
                    .add_scalar_poly(B::F::one()))
                * &mask;
            let lifted = &(&breaks * &(data_rotated - data))
                + &breaks.mul_scalar_poly(-c).add_scalar_poly(c);
            prover.add_mv_nozerocheck_claim(lifted.id())?;
        }
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
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let (Some(ties), Some(input), Some(rotated)) = (
            payload.get(TIE_INDICATOR_LABEL),
            payload.get(TABLE_LABEL),
            payload.get(ROTATED_INPUT_LABEL),
        ) else {
            return Ok(());
        };
        if let Some(check) = payload.get(LIMBS_LABEL) {
            self.verify_limbs(verifier, check)?;
        }
        let sort_specs = sort_specs_for_table_verifier(&self.sort_config, input);
        let columns = sort_columns_verifier(input, rotated, &sort_specs);
        let ties: Vec<_> = ties
            .data_tracked_oracles_indices()
            .into_iter()
            .map(|idx| ties.tracked_col_oracle_by_ind(idx).data_tracked_oracle())
            .collect();
        let mask = rotated
            .activator_tracked_poly()
            .expect("the rotated table carries the mask C_{µ,s-1}");
        if columns.len() < 2 {
            return Ok(());
        }
        let c = verifier.get_and_append_challenge(b"sort_tie_break")?;
        for (k, (data, data_rotated)) in columns.iter().enumerate().take(columns.len() - 1) {
            let breaks = &(&ties[k]
                * &ties[k + 1]
                    .mul_scalar_oracle(-B::F::one())
                    .add_scalar_oracle(B::F::one()))
                * &mask;
            let lifted = &(&breaks * &(data_rotated - data))
                + &breaks.mul_scalar_oracle(-c).add_scalar_oracle(c);
            verifier.add_mv_nozerocheck_claim(lifted.id());
        }
        Ok(())
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

fn missing_column(name: &str) -> SnarkError {
    SnarkError::Artifact(format!("the distinct sort's input lacks {name}"))
}

impl<B: SnarkBackend> GadgetNode<B> {
    /// In the distinct mode, replaces `input` in `payload` by the compared
    /// view, and the committed limbs by the table the limb checks read: each
    /// hash slot, its limbs and the activator.
    fn distinct_view_prover(
        &self,
        input: TrackedTable<B>,
        payload: &mut IndexMap<String, TrackedTable<B>>,
    ) -> SnarkResult<TrackedTable<B>> {
        let SortConfig::Distinct = self.sort_config else {
            return Ok(input);
        };
        let polys = input.tracked_polys();
        let layout = DistinctLayout::new::<B::F>(polys.keys().map(|field| field.as_ref()))
            .map_err(|e| SnarkError::Artifact(e.to_string()))?;
        let limbs = payload
            .get(LIMBS_LABEL)
            .map(|table| table.tracked_polys())
            .unwrap_or_default();
        let find = |name: &str| {
            polys
                .iter()
                .chain(limbs.iter())
                .find(|(field, _)| field.name() == name)
                .map(|(field, poly)| (field.clone(), poly.clone()))
                .ok_or_else(|| missing_column(name))
        };
        let activator = input.activator_tracked_poly();
        let mut view = IndexMap::new();
        for field in &layout.sort_fields {
            let (field, poly) = find(field.name())?;
            view.insert(field, poly);
        }
        view.extend(
            activator
                .clone()
                .map(|poly| (ACTIVATOR_FIELD.clone(), poly)),
        );
        if !layout.slots.is_empty() {
            let mut check = IndexMap::new();
            for slot in &layout.slots {
                let (field, poly) = find(&slot.name())?;
                check.insert(field, poly);
                for (limb, _) in &slot.limbs {
                    let (field, poly) = find(limb.name())?;
                    check.insert(field, poly);
                }
            }
            check.extend(activator.map(|poly| (ACTIVATOR_FIELD.clone(), poly)));
            payload.insert(
                LIMBS_LABEL.to_string(),
                TrackedTable::new(None, check, input.log_size()),
            );
        }
        let view = TrackedTable::new(None, view, input.log_size());
        payload.insert(TABLE_LABEL.to_string(), view.clone());
        *self.distinct_layout.lock().expect("lock poisoned") = Some(layout);
        Ok(view)
    }

    fn distinct_view_verifier(
        &self,
        input: TrackedTableOracle<B>,
        payload: &mut IndexMap<String, TrackedTableOracle<B>>,
    ) -> SnarkResult<TrackedTableOracle<B>> {
        let SortConfig::Distinct = self.sort_config else {
            return Ok(input);
        };
        let oracles = input.tracked_oracles();
        let layout = DistinctLayout::new::<B::F>(oracles.keys().map(|field| field.as_ref()))
            .map_err(|e| SnarkError::Artifact(e.to_string()))?;
        let limbs = payload
            .get(LIMBS_LABEL)
            .map(|table| table.tracked_oracles())
            .unwrap_or_default();
        let find = |name: &str| {
            oracles
                .iter()
                .chain(limbs.iter())
                .find(|(field, _)| field.name() == name)
                .map(|(field, oracle)| (field.clone(), oracle.clone()))
                .ok_or_else(|| missing_column(name))
        };
        let activator = input.activator_tracked_poly();
        let mut view = IndexMap::new();
        for field in &layout.sort_fields {
            let (field, oracle) = find(field.name())?;
            view.insert(field, oracle);
        }
        view.extend(
            activator
                .clone()
                .map(|oracle| (ACTIVATOR_FIELD.clone(), oracle)),
        );
        if !layout.slots.is_empty() {
            let mut check = IndexMap::new();
            for slot in &layout.slots {
                let (field, oracle) = find(&slot.name())?;
                check.insert(field, oracle);
                for (limb, _) in &slot.limbs {
                    let (field, oracle) = find(limb.name())?;
                    check.insert(field, oracle);
                }
            }
            check.extend(activator.map(|oracle| (ACTIVATOR_FIELD.clone(), oracle)));
            payload.insert(
                LIMBS_LABEL.to_string(),
                TrackedTableOracle::new(None, check, input.log_size()),
            );
        }
        let view = TrackedTableOracle::new(None, view, input.log_size());
        payload.insert(TABLE_LABEL.to_string(), view.clone());
        *self.distinct_layout.lock().expect("lock poisoned") = Some(layout);
        Ok(view)
    }

    /// Each hash slot equals the integer of its limbs, and each limb is
    /// within its width, on the active rows.
    fn prove_limbs(&self, prover: &mut ArgProver<B>, check: &TrackedTable<B>) -> SnarkResult<()> {
        let layout = self.distinct_layout.lock().expect("lock poisoned").clone();
        let layout = layout.expect("the distinct layout is read in initialize_gadgets");
        let activator = check
            .activator_tracked_poly()
            .expect("the distinct sort's input has an activator");
        let polys = check.tracked_polys();
        let poly = |name: &str| {
            polys
                .iter()
                .find(|(field, _)| field.name() == name)
                .map(|(_, poly)| poly.clone())
                .expect("the limb check table holds every slot and limb")
        };
        for slot in &layout.slots {
            let mut limbs = slot.limbs.iter();
            let (top, _) = limbs.next().expect("a hash slot has limbs");
            let recomposed = limbs.fold(poly(top.name()), |acc, (limb, width)| {
                &acc.mul_scalar_poly(B::F::from(1u64 << width)) + &poly(limb.name())
            });
            let difference = &(&poly(&slot.name()) - &recomposed) * &activator;
            prover.add_mv_zerocheck_claim(difference.id())?;
            for (limb, width) in &slot.limbs {
                let col = check
                    .tracked_col_by_name(limb.name())
                    .expect("the limb check table holds every limb");
                sign::SignNode::<B>::add_range_inclusion(prover, &col, *width as usize)?;
            }
        }
        Ok(())
    }

    fn verify_limbs(
        &self,
        verifier: &mut ArgVerifier<B>,
        check: &TrackedTableOracle<B>,
    ) -> SnarkResult<()> {
        let layout = self.distinct_layout.lock().expect("lock poisoned").clone();
        let layout = layout.expect("the distinct layout is read in initialize_gadgets");
        let activator = check
            .activator_tracked_poly()
            .expect("the distinct sort's input has an activator");
        let oracles = check.tracked_oracles();
        let oracle = |name: &str| {
            oracles
                .iter()
                .find(|(field, _)| field.name() == name)
                .map(|(_, oracle)| oracle.clone())
                .expect("the limb check table holds every slot and limb")
        };
        for slot in &layout.slots {
            let mut limbs = slot.limbs.iter();
            let (top, _) = limbs.next().expect("a hash slot has limbs");
            let recomposed = limbs.fold(oracle(top.name()), |acc, (limb, width)| {
                &acc.mul_scalar_oracle(B::F::from(1u64 << width)) + &oracle(limb.name())
            });
            let difference = &(&oracle(&slot.name()) - &recomposed) * &activator;
            verifier.add_mv_zerocheck_claim(difference.id());
            for (limb, width) in &slot.limbs {
                let col = check
                    .tracked_col_oracle_by_name(limb.name())
                    .expect("the limb check table holds every limb");
                sign::SignNode::<B>::add_range_inclusion_oracle(verifier, &col, *width as usize)?;
            }
        }
        Ok(())
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
        let perm = Arc::new(Node::<B>::Gadget(Arc::new(perm::GadgetNode::new())));
        let bool_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::utils::bool::GadgetNode::new(),
        )));
        let sign_gadget = build_sign_gadget::<B>(&sort_config);
        Self {
            perm,
            bool_gadget,
            sign_gadget,
            sort_config,
            strip_row_id,
            distinct_layout: std::sync::Mutex::new(None),
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
        SortConfig::Distinct => {
            sign::SignConfig::SemiUniform(sign::Sign::NonNegative, sign::Sign::Positive)
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
        SortConfig::Distinct => input_hint
            .data_frame()
            .schema()
            .fields()
            .iter()
            .filter(|field| !arithmetic::is_system_column(field.name()))
            .map(|field| (field.name().to_string(), true, true))
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
    if ordered.len() == sort_specs.len() {
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
        .filter(|field| {
            field.name() != ROW_ID_COL_NAME && field.name() != arithmetic::ACTIVATOR_COL_NAME
        })
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
/// binary). The distinct mode compares such a key on its hash limbs; an
/// ORDER BY compares it through a committed sign-only diff in `{0, 1, 2}`,
/// which is not bound to the key.
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
        SortConfig::Distinct => input_table
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
                (field.name().to_string(), true, true)
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
        SortConfig::Distinct => input_table
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
                (field.name().to_string(), true, true)
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

/// Each sort key's column in the input and in the rotated table, in key
/// order.
fn sort_columns_prover<B: SnarkBackend>(
    input: &TrackedTable<B>,
    rotated: &TrackedTable<B>,
    sort_specs: &[(String, bool, bool)],
) -> Vec<(TrackedPoly<B>, TrackedPoly<B>)> {
    ordered_data_indices_prover(input, sort_specs)
        .into_iter()
        .zip(ordered_data_indices_prover(rotated, sort_specs))
        .map(|(i, r)| {
            (
                input.tracked_col_by_ind(i).data_tracked_poly(),
                rotated.tracked_col_by_ind(r).data_tracked_poly(),
            )
        })
        .collect()
}

fn sort_columns_verifier<B: SnarkBackend>(
    input: &TrackedTableOracle<B>,
    rotated: &TrackedTableOracle<B>,
    sort_specs: &[(String, bool, bool)],
) -> Vec<(TrackedOracle<B>, TrackedOracle<B>)> {
    ordered_data_indices_verifier(input, sort_specs)
        .into_iter()
        .zip(ordered_data_indices_verifier(rotated, sort_specs))
        .map(|(i, r)| {
            (
                input.tracked_col_oracle_by_ind(i).data_tracked_oracle(),
                rotated.tracked_col_oracle_by_ind(r).data_tracked_oracle(),
            )
        })
        .collect()
}

/// The rotated table with the public mask `C_{µ,s-1}` as its activator: the
/// rows it is compared on.
fn with_activator_prover<B: SnarkBackend>(
    table: &TrackedTable<B>,
    activator: TrackedPoly<B>,
) -> TrackedTable<B> {
    let mut polys = table.tracked_polys();
    polys.insert(ACTIVATOR_FIELD.clone(), activator);
    TrackedTable::new(None, polys, table.log_size())
}

fn with_activator_verifier<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    activator: TrackedOracle<B>,
) -> TrackedTableOracle<B> {
    let mut oracles = table.tracked_oracles();
    oracles.insert(ACTIVATOR_FIELD.clone(), activator);
    TrackedTableOracle::new(None, oracles, table.log_size())
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
            SortConfig::Distinct => sign_for_column(true, true),
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

    // Compared on the rows of the mask `C_{µ,s-1}`, the rotated table's activator.
    if let Some(activator) = rotated_table.activator_tracked_poly() {
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
            SortConfig::Distinct => sign_for_column(true, true),
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

    // Compared on the rows of the mask `C_{µ,s-1}`, the rotated table's activator.
    if let Some(activator) = rotated_table.activator_tracked_poly() {
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

/// Puts the public `tie_0 = C_{µ,s-1}` in front of the committed ties
/// `tie_1..` (paper PIOP 7, step 2: the verifier sets ties_0). It is the
/// comparison mask: row `j` is compared with row `j + 1` for `j < s - 1`. A
/// supplied `tie_0` is dropped: a committed one would let the prover switch
/// every comparison off.
fn prepend_first_tie_indicator_prover<B: SnarkBackend>(
    committed: Option<&TrackedTable<B>>,
    mask: TrackedPoly<B>,
) -> TrackedTable<B> {
    let log_size = mask.log_size();
    let mut tracked_polys = IndexMap::new();
    tracked_polys.insert(first_tie_field(), mask);
    for (field, poly) in committed
        .iter()
        .flat_map(|table| table.tracked_polys_iter())
    {
        if field.name() != FIRST_TIE_LABEL {
            tracked_polys.insert(field.clone(), poly.clone());
        }
    }
    TrackedTable::new(None, tracked_polys, log_size)
}

fn prepend_first_tie_indicator_verifier<B: SnarkBackend>(
    committed: Option<&TrackedTableOracle<B>>,
    mask: TrackedOracle<B>,
) -> TrackedTableOracle<B> {
    let log_size = mask.log_size();
    let mut tracked_oracles = IndexMap::new();
    tracked_oracles.insert(first_tie_field(), mask);
    for (field, oracle) in committed
        .iter()
        .flat_map(|table| table.tracked_oracles_iter())
    {
        if field.name() != FIRST_TIE_LABEL {
            tracked_oracles.insert(field.clone(), oracle.clone());
        }
    }
    TrackedTableOracle::new(None, tracked_oracles, log_size)
}

fn first_tie_field() -> FieldRef {
    Arc::new(Field::new(FIRST_TIE_LABEL, DataType::Boolean, false))
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

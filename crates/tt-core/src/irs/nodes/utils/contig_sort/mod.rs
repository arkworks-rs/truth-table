use crate::session::session_context;
use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_FIELD, ROW_ID_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_ff::One;
use ark_piop::SnarkBackend;
use ark_piop::arithmetic::errors::DataTypeError;
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
use indexmap::IndexMap;

use crate::irs::nodes::utils::{field_to_usize, sign};
use crate::{
    irs::{
        nodes::{
            IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps,
            utils::contig_sort::hints::{populate_rotated, populate_ties},
        },
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};
mod distinct;
mod hints;
pub mod piop;
pub mod rotation;
#[cfg(test)]
pub(crate) mod tests;

pub const TABLE_LABEL: &str = "__input__";
pub const ROTATED_INPUT_LABEL: &str = "__rotated_input__";
pub const TIE_INDICATOR_LABEL: &str = "__tie_indicator__";
/// A zero-variable table holding `s`, the number of active rows. The input's
/// activator must be `C_{µ,s}`: the check covers its first `s` rows.
pub const ACTIVE_ROWS_LABEL: &str = "__active_rows__";

/// The column of the [`ACTIVE_ROWS_LABEL`] table.
pub fn active_rows_field() -> FieldRef {
    Arc::new(Field::new("active_rows", DataType::UInt64, false))
}

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

/// `sort_specs` are `(column, ascending, nulls first)` in key order; each
/// names exactly one column of the sorted table.
pub struct PerColumnConfig {
    pub sort_specs: Vec<(String, bool, bool)>,
    pub strict: bool,
}

/// Enforces that a table is sorted according to its sort config: the sort
/// check ([`piop`]) on the planned table, with the rotated keys and the tie
/// indicators taken from the hints.
pub struct GadgetNode<B: SnarkBackend> {
    sort_config: SortConfig,
    strip_row_id: bool,
    /// The distinct mode's layout, read from the input table.
    distinct_layout: std::sync::Mutex<Option<DistinctLayout>>,
    _backend: std::marker::PhantomData<B>,
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
        Vec::new()
    }
}

/// The number of active rows `s` the caller passes under
/// [`ACTIVE_ROWS_LABEL`]: the input's activator is `C_{µ,s}`.
pub(crate) fn active_rows_prover<B: SnarkBackend>(table: &TrackedTable<B>) -> SnarkResult<usize> {
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

pub(crate) fn active_rows_verifier<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
) -> SnarkResult<usize> {
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
pub(crate) fn shift_tables_prover<B: SnarkBackend>(
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

pub(crate) fn shift_tables_verifier<B: SnarkBackend>(
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
    #[cfg(feature = "test-utils")]
    let sort_specs = match node.sort_config {
        SortConfig::PerColumn(_) if !is_verifier => {
            crate::test_utils::dishonest_prover::forge_sort_specs(sort_specs)
        }
        _ => sort_specs,
    };
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
        let key_count = hint_key_positions(&sorted_input_hint, &sort_specs)
            .map_err(SnarkError::Artifact)?
            .len();
        gadget_payload.insert(
            ROTATED_INPUT_LABEL.to_string(),
            build_verifier_rotated_hint(&sorted_input_hint),
        );
        if let Some(tie_hint) = build_verifier_tie_hint(key_count) {
            gadget_payload.insert(TIE_INDICATOR_LABEL.to_string(), tie_hint);
        }
    } else {
        populate_rotated(&mut gadget_payload, &sorted_input_hint, &sort_specs, false);
        populate_ties(&mut gadget_payload, &sorted_input_hint, &sort_specs);
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
        _prover: &mut ark_piop::prover::ArgProver<B>,
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
        self.distinct_view_prover(input, &mut payload)?;
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
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
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
        self.distinct_view_verifier(input, &mut payload)?;
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
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let (Some(input), Some(rotated), Some(count)) = (
            payload.get(TABLE_LABEL),
            payload.get(ROTATED_INPUT_LABEL),
            payload.get(ACTIVE_ROWS_LABEL),
        ) else {
            return Ok(());
        };
        if let Some(check) = payload.get(LIMBS_LABEL) {
            self.prove_limbs(prover, check)?;
        }
        let s = active_rows_prover(count)?;
        let log_size = input.log_size();
        let sort_specs = sort_specs_for_table_prover(&self.sort_config, input);
        let keys = sort_keys_prover(input, rotated, &sort_specs)?;
        let pairs: Vec<_> = keys
            .iter()
            .map(|key| (key.data.clone(), key.next.clone()))
            .collect();
        rotation::prove(prover, &pairs, log_size, s)?;
        let ties: Vec<_> = payload
            .get(TIE_INDICATOR_LABEL)
            .map(|table| {
                table
                    .data_tracked_polys_indices()
                    .into_iter()
                    .map(|idx| table.tracked_col_by_ind(idx).data_tracked_poly())
                    .collect()
            })
            .unwrap_or_default();
        let start = piop::Tie::mask(prover, log_size, s)?;
        piop::prove_with_ties(prover, &keys, start, self.end(), &ties)?;
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
        let (Some(input), Some(rotated), Some(count)) = (
            payload.get(TABLE_LABEL),
            payload.get(ROTATED_INPUT_LABEL),
            payload.get(ACTIVE_ROWS_LABEL),
        ) else {
            return Ok(());
        };
        if let Some(check) = payload.get(LIMBS_LABEL) {
            self.verify_limbs(verifier, check)?;
        }
        let s = active_rows_verifier(count)?;
        let log_size = input.log_size();
        let sort_specs = sort_specs_for_table_verifier(&self.sort_config, input);
        let keys = sort_keys_verifier(input, rotated, &sort_specs)?;
        let pairs: Vec<_> = keys
            .iter()
            .map(|key| (key.data.clone(), key.next.clone()))
            .collect();
        rotation::verify(verifier, &pairs, log_size, s)?;
        let ties: Vec<_> = payload
            .get(TIE_INDICATOR_LABEL)
            .map(|table| {
                table
                    .data_tracked_oracles_indices()
                    .into_iter()
                    .map(|idx| table.tracked_col_oracle_by_ind(idx).data_tracked_oracle())
                    .collect()
            })
            .unwrap_or_default();
        let start = piop::Tie::mask_oracle(verifier, log_size, s)?;
        piop::verify_with_ties(verifier, &keys, start, self.end(), &ties)?;
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
    /// A distinct sort is strict: no two rows are equal.
    fn end(&self) -> piop::End {
        match &self.sort_config {
            SortConfig::Distinct => piop::End::Strict,
            SortConfig::PerColumn(config) if config.strict => piop::End::Strict,
            SortConfig::PerColumn(_) => piop::End::NonStrict,
        }
    }

    pub fn new(sort_config: SortConfig) -> Self {
        Self::new_internal(sort_config, true)
    }

    pub fn new_preserve_row_id(sort_config: SortConfig) -> Self {
        Self::new_internal(sort_config, false)
    }

    fn new_internal(sort_config: SortConfig, strip_row_id: bool) -> Self {
        Self {
            sort_config,
            strip_row_id,
            distinct_layout: std::sync::Mutex::new(None),
            _backend: std::marker::PhantomData,
        }
    }
}

// Use a forward-difference sign check so contig-sort only enforces monotonicity.
/// The position among `names` of each sort key, in key order. A key names
/// exactly one column: a missing or ambiguous key is an error, never a
/// fallback to other columns.
pub(crate) fn key_positions<'a>(
    names: impl IntoIterator<Item = &'a str>,
    sort_specs: &[(String, bool, bool)],
) -> Result<Vec<usize>, String> {
    let names: Vec<&str> = names.into_iter().collect();
    sort_specs
        .iter()
        .map(|(key, _, _)| {
            let mut matches = names
                .iter()
                .enumerate()
                .filter(|(_, name)| **name == key.as_str());
            match (matches.next(), matches.next()) {
                (Some((position, _)), None) => Ok(position),
                (None, _) => Err(format!(
                    "the sort key {key} names no column of the sorted table"
                )),
                (Some(_), Some(_)) => Err(format!(
                    "the sort key {key} names more than one column of the sorted table"
                )),
            }
        })
        .collect()
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

/// The position among the data fields of `hint` of each sort key.
fn hint_key_positions(
    hint: &crate::irs::nodes::hints::HintDF,
    sort_specs: &[(String, bool, bool)],
) -> Result<Vec<usize>, String> {
    let schema = hint.data_frame().schema();
    let names = schema
        .fields()
        .iter()
        .map(|field| field.name().as_str())
        .filter(|name| !arithmetic::is_system_column(name));
    key_positions(names, sort_specs)
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

fn build_verifier_tie_hint(key_count: usize) -> Option<crate::irs::nodes::hints::HintDF> {
    if key_count < 2 {
        return None;
    }
    let fields = (1..key_count)
        .map(|idx| Field::new(format!("tie_{idx}"), DataType::Boolean, true))
        .collect();
    Some(build_empty_hint_df_with_fields(fields, true))
}

/// The unsigned type whose width bounds the adjacent difference
/// `rotated - input` of a sort key ([`piop::key_width`]). Signed values
/// encode as field negations, so the difference is the integer one, and a
/// non-decreasing pair gives a value in `[0, 2^w)` for that width `w`.
///
/// `None` when the encoding does not preserve the key's order (strings,
/// binary, floats): such a key cannot be sorted on. A string key is sorted
/// on its rank instead (TruthTable++ Rank-Based String Sort Check, §7.3, PIOP 13).
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

/// The flat index in `table` of each sort key's column, in key order.
fn ordered_data_indices_prover<B: SnarkBackend>(
    table: &TrackedTable<B>,
    sort_specs: &[(String, bool, bool)],
) -> SnarkResult<Vec<usize>> {
    let data_indices = non_row_id_data_indices_prover(table);
    let names: Vec<String> = data_indices
        .iter()
        .map(|idx| {
            table
                .tracked_col_by_ind(*idx)
                .field_ref()
                .expect("a field")
                .name()
                .clone()
        })
        .collect();
    let positions =
        key_positions(names.iter().map(String::as_str), sort_specs).map_err(sort_key_error)?;
    Ok(positions
        .into_iter()
        .map(|position| data_indices[position])
        .collect())
}

fn ordered_data_indices_verifier<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    sort_specs: &[(String, bool, bool)],
) -> SnarkResult<Vec<usize>> {
    let data_indices = non_row_id_data_indices_verifier(table);
    let names: Vec<String> = data_indices
        .iter()
        .map(|idx| {
            table
                .tracked_col_oracle_by_ind(*idx)
                .field_ref()
                .expect("a field")
                .name()
                .clone()
        })
        .collect();
    let positions =
        key_positions(names.iter().map(String::as_str), sort_specs).map_err(sort_key_error)?;
    Ok(positions
        .into_iter()
        .map(|position| data_indices[position])
        .collect())
}

fn sort_key_error(message: String) -> SnarkError {
    SnarkError::DataTypeError(DataTypeError::NotSupported(message))
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
/// order, with its direction and the width of its adjacent difference.
fn sort_keys_prover<B: SnarkBackend>(
    input: &TrackedTable<B>,
    rotated: &TrackedTable<B>,
    sort_specs: &[(String, bool, bool)],
) -> SnarkResult<Vec<piop::SortKey<TrackedPoly<B>>>> {
    ordered_data_indices_prover(input, sort_specs)?
        .into_iter()
        .zip(ordered_data_indices_prover(rotated, sort_specs)?)
        .zip(sort_specs)
        .map(|((i, r), (_, asc, _))| {
            let col = input.tracked_col_by_ind(i);
            let field = col.field_ref().expect("a field");
            Ok(piop::SortKey {
                data: col.data_tracked_poly(),
                next: rotated.tracked_col_by_ind(r).data_tracked_poly(),
                asc: *asc,
                width: sort_key_width(&field)?,
            })
        })
        .collect()
}

fn sort_keys_verifier<B: SnarkBackend>(
    input: &TrackedTableOracle<B>,
    rotated: &TrackedTableOracle<B>,
    sort_specs: &[(String, bool, bool)],
) -> SnarkResult<Vec<piop::SortKey<TrackedOracle<B>>>> {
    ordered_data_indices_verifier(input, sort_specs)?
        .into_iter()
        .zip(ordered_data_indices_verifier(rotated, sort_specs)?)
        .zip(sort_specs)
        .map(|((i, r), (_, asc, _))| {
            let col = input.tracked_col_oracle_by_ind(i);
            let field = col.field_ref().expect("a field");
            Ok(piop::SortKey {
                data: col.data_tracked_oracle(),
                next: rotated.tracked_col_oracle_by_ind(r).data_tracked_oracle(),
                asc: *asc,
                width: sort_key_width(&field)?,
            })
        })
        .collect()
}

fn sort_key_width(field: &Field) -> SnarkResult<usize> {
    piop::key_width(field.data_type()).ok_or_else(|| {
        sort_key_error(format!(
            "the sort key {} of type {} has no order-preserving encoding",
            field.name(),
            field.data_type()
        ))
    })
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

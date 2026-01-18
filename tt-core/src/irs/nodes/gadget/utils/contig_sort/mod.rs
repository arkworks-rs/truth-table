use std::sync::Arc;

use arithmetic::{ROW_ID_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::One;
use ark_piop::SnarkBackend;
use ark_piop::arithmetic::mat_poly::utils::{build_eq_x_r, build_sparse_eq_x_r};
use ark_piop::verifier::structs::oracle::Oracle;
use ark_piop::{
    prover::ArgProver, prover::structs::polynomial::TrackedPoly, verifier::ArgVerifier,
    verifier::structs::oracle::TrackedOracle,
};
use ark_poly::Polynomial;
use datafusion::arrow::{
    array::{ArrayRef, BooleanArray, Int64Array},
    compute::{concat, concat_batches},
    datatypes::{DataType, Field, Schema},
    record_batch::RecordBatch,
};
use datafusion::datasource::MemTable;
use datafusion::prelude::SessionContext;
use datafusion_common::{DFSchema, DataFusionError, ScalarValue};
use either::Either;
use indexmap::IndexMap;

use crate::irs::nodes::gadget::utils::{neq, prescr_perm, sign};
use crate::{
    irs::{
        nodes::{
            IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps,
            gadget::utils::contig_sort::hints::{
                populate_diff, populate_rotated, populate_tie_indicator,
            },
        },
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};
mod hints;
#[cfg(test)]
mod tests;

// Pad contig-sort hints to a power-of-two row count for circuit alignment.
fn pad_df_to_power_of_two(
    df: datafusion::prelude::DataFrame,
) -> datafusion_common::Result<datafusion::prelude::DataFrame> {
    let schema_ref = df.schema();
    let arrow_schema: Schema = <DFSchema as AsRef<Schema>>::as_ref(schema_ref).clone();
    let batches = collect_blocking(df)?;
    let (batches, row_count) = pad_batches_to_power_of_two(&arrow_schema, batches)?;
    if batches.is_empty() {
        return Err(DataFusionError::Execution(
            "contig sort padding produced empty batches".to_string(),
        ));
    }
    let mem_table = MemTable::try_new(Arc::new(arrow_schema), vec![batches])
        .map_err(|e| DataFusionError::Execution(e.to_string()))?;
    let ctx = SessionContext::new();
    let padded_df = ctx
        .read_table(Arc::new(mem_table))
        .map_err(|e| DataFusionError::Execution(e.to_string()))?;
    Ok(padded_df)
}

// Collect a DataFrame from both async and non-async contexts.
fn collect_blocking(
    df: datafusion::prelude::DataFrame,
) -> datafusion_common::Result<Vec<RecordBatch>> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => match handle.runtime_flavor() {
            tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(df.collect()))
            }
            tokio::runtime::RuntimeFlavor::CurrentThread => {
                let df_clone = df.clone();
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| DataFusionError::Execution(e.to_string()))?;
                    rt.block_on(df_clone.collect())
                })
                .join()
                .map_err(|_| {
                    DataFusionError::Execution("dataframe collection thread panicked".to_string())
                })?
            }
            _ => tokio::task::block_in_place(|| handle.block_on(df.collect())),
        },
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| DataFusionError::Execution(e.to_string()))?;
            rt.block_on(df.collect())
        }
    }
}

// Pad batches to a power-of-two row count, preserving system columns.
fn pad_batches_to_power_of_two(
    schema: &Schema,
    batches: Vec<RecordBatch>,
) -> datafusion_common::Result<(Vec<RecordBatch>, usize)> {
    let row_count: usize = batches.iter().map(|b| b.num_rows()).sum();
    let target = if row_count == 0 {
        1
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
        } else if field.name() == ROW_ID_COL_NAME {
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

/// Labels for different gadget payloads used by this gadget.
pub const TABLE_LABEL: &str = "__input__";
pub const ROTATED_INPUT_LABEL: &str = "__rotated_input__";
pub const TIE_INDICATOR_LABEL: &str = "__tie_indicator__";
pub const DIFF_INPUT_LABEL: &str = "__diff_input__";
const FIRST_TIE_LABEL: &str = "tie_0";

/// GadgetNode for enforcing sorting of a table according to specified sort expressions.
pub struct GadgetNode<B: SnarkBackend> {
    prescr_perm: Arc<Node<B>>,
    bool_gadget: Arc<Node<B>>,
    sign_gadgets: Vec<Arc<Node<B>>>,
    sign_gadget_names: Vec<String>,
    neq_gadgets: Vec<Arc<Node<B>>>,
    sort_specs: Vec<(String, bool, bool)>,
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
        let sorted_input_hint = {
            let sorted_df =
                crate::irs::nodes::gadget::utils::contig_sort::hints::sort_input_for_contig_sort(
                    &input_hint,
                    &self.sort_specs,
                )
                .expect("contig sort ordering should succeed");
            let padded_df = pad_df_to_power_of_two(sorted_df)
                .expect("contig sort input padding should succeed");
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

        populate_rotated(&mut gadget_payload, &sorted_input_hint, &self.sort_specs);
        populate_tie_indicator(&mut gadget_payload, &sorted_input_hint, &self.sort_specs);
        populate_diff(&mut gadget_payload, &sorted_input_hint, &self.sort_specs);
        // Strip row-id before storing to avoid exposing it in gadget payloads.
        let sanitized_input = crate::irs::nodes::hints::strip_row_id_from_hint(&sorted_input_hint);
        gadget_payload.insert(TABLE_LABEL.to_string(), sanitized_input);
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));
        Ok(())
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        let mut children = vec![self.prescr_perm.clone(), self.bool_gadget.clone()];
        children.extend(self.sign_gadgets.iter().cloned());
        children.extend(self.neq_gadgets.iter().cloned());
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
        } else if let Some(input_table) = payload.get(TABLE_LABEL).cloned() {
            // For single-key sorts the tie table can be dropped during materialization; keep
            // a no-op Bool payload so the Bool gadget doesn't panic.
            let mut bool_payload = match virtualized_ir.payload_for_node(&self.bool_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            bool_payload.insert(
                crate::irs::nodes::gadget::utils::bool::TABLE_LABEL.to_string(),
                TrackedTable::new(None, IndexMap::new(), input_table.log_size()),
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
            // Prefer precomputed diffs so sign gadgets operate on bounded values.
            let diff_table = payload.get(DIFF_INPUT_LABEL).cloned();
            populate_sign_payloads_prover(
                &self.sign_gadgets,
                &self.sign_gadget_names,
                &self.sort_specs,
                diff_table.as_ref(),
                &tie_table,
                &input_table,
                &rotated_table,
                virtualized_ir,
            )?;
            populate_neq_payloads_prover(
                &self.neq_gadgets,
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
        } else if let Some(input_table) = payload.get(TABLE_LABEL).cloned() {
            // For single-key sorts the tie table can be dropped during materialization; keep
            // a no-op Bool payload so the Bool gadget doesn't panic.
            let mut bool_payload = match virtualized_ir.payload_for_node(&self.bool_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            bool_payload.insert(
                crate::irs::nodes::gadget::utils::bool::TABLE_LABEL.to_string(),
                TrackedTableOracle::new(None, IndexMap::new(), input_table.log_size()),
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
            let diff_table = payload.get(DIFF_INPUT_LABEL).cloned();
            populate_sign_payloads_verifier(
                &self.sign_gadgets,
                &self.sign_gadget_names,
                &self.sort_specs,
                diff_table.as_ref(),
                &tie_table,
                &input_table,
                &rotated_table,
                virtualized_ir,
            )?;
            populate_neq_payloads_verifier(
                &self.neq_gadgets,
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
        add_tie_rotation_consistency_zerochecks_prover(prover, gadget_ready_ir, id)?;
        Ok(())
    }

    fn honest_prover_check(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
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

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(sort_specs: Vec<(String, bool, bool)>, strict: bool) -> Self {
        let sign_gadget_names: Vec<String> = sort_specs
            .iter()
            .map(|(name, _, _)| normalize_sort_name(name))
            .collect();
        let asc: Vec<bool> = sort_specs.iter().map(|(_, asc, _)| *asc).collect();
        let prescr_perm = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::prescr_perm::GadgetNode::new(),
        )));
        let bool_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::bool::GadgetNode::new(),
        )));
        let sign_gadgets = build_sign_gadgets::<B>(&asc, strict);
        let neq_gadgets = build_neq_gadgets::<B>(asc.len().saturating_sub(1));
        Self {
            prescr_perm,
            bool_gadget,
            sign_gadgets,
            sign_gadget_names,
            neq_gadgets,
            sort_specs,
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

fn build_sign_gadgets<B: SnarkBackend>(asc: &[bool], strict: bool) -> Vec<Arc<Node<B>>> {
    let last_idx = asc.len().saturating_sub(1);
    asc.iter()
        .enumerate()
        .map(|(idx, &is_asc)| {
            let strict_for_col = strict && idx == last_idx;
            let sign = sign_for_column(is_asc, strict_for_col);
            Arc::new(Node::<B>::Gadget(Arc::new(sign::SignNode::new(
                sign::SignConfig::Uniform(sign),
            ))))
        })
        .collect()
}

fn build_neq_gadgets<B: SnarkBackend>(count: usize) -> Vec<Arc<Node<B>>> {
    (0..count)
        .map(|_| {
            Arc::new(Node::<B>::Gadget(Arc::new(
                crate::irs::nodes::gadget::utils::neq::GadgetNode::new(),
            )))
        })
        .collect()
}

fn normalize_sort_name(name: &str) -> String {
    name.rsplit('.').next().unwrap_or(name).to_string()
}

fn sort_is_asc(sort_specs: &[(String, bool, bool)], col_name: &str) -> bool {
    sort_specs
        .iter()
        .find(|(name, _, _)| normalize_sort_name(name) == col_name)
        .map(|(_, asc, _)| *asc)
        .unwrap_or(true)
}

fn populate_sign_payloads_prover<B: SnarkBackend>(
    sign_gadgets: &[Arc<Node<B>>],
    sign_gadget_names: &[String],
    sort_specs: &[(String, bool, bool)],
    diff_table: Option<&TrackedTable<B>>,
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
        sign_gadget_names.len(),
        "Sort gadget expects name for each sign gadget."
    );
    for ((tie_idx, input_idx), rotated_idx) in tie_indices
        .iter()
        .copied()
        .zip(input_indices.iter().copied())
        .zip(rotated_indices.iter().copied())
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
        let sign_pos = sign_gadget_names
            .iter()
            .position(|name| name == &col_name)
            .unwrap_or_else(|| {
                panic!("Missing sign gadget for Sort column {}", col_name);
            });
        let sign_gadget = &sign_gadgets[sign_pos];
        // When diffs are materialized, use their column type for sign checks.
        let (diff_poly, diff_field) = if let Some(diff_table) = diff_table {
            let diff_idx = diff_table
                .data_tracked_polys_indices()
                .into_iter()
                .find(|idx| {
                    let diff_field = diff_table
                        .tracked_col_by_ind(*idx)
                        .field_ref()
                        .expect("Expected field ref for diff column");
                    normalize_sort_name(diff_field.name()) == col_name
                })
                .unwrap_or_else(|| panic!("Missing diff column for Sort column {}", col_name));
            let diff_col = diff_table.tracked_col_by_ind(diff_idx);
            let diff_field = diff_col
                .field_ref()
                .expect("Expected field ref for diff column")
                .as_ref()
                .clone();
            (diff_col.data_tracked_poly(), diff_field)
        } else if is_asc {
            (
                &rotated_col.data_tracked_poly() - &input_col.data_tracked_poly(),
                input_col
                    .field_ref()
                    .expect("Expected field ref for Sort sign input")
                    .as_ref()
                    .clone(),
            )
        } else {
            (
                &input_col.data_tracked_poly() - &rotated_col.data_tracked_poly(),
                input_col
                    .field_ref()
                    .expect("Expected field ref for Sort sign input")
                    .as_ref()
                    .clone(),
            )
        };
        let data_field = Arc::new(diff_field);
        let input_activator = input_table.activator_tracked_poly();
        let rotated_activator = rotated_table.activator_tracked_poly();
        let mut combined_activator = tie_col.data_tracked_poly();
        if let Some(input_act) = input_activator {
            combined_activator = &combined_activator * &input_act;
        }
        if let Some(rotated_act) = rotated_activator {
            combined_activator = &combined_activator * &rotated_act;
        }
        let sign_input = TrackedTable::single_column_with_activator(
            data_field,
            diff_poly,
            Some(combined_activator),
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
    sign_gadget_names: &[String],
    sort_specs: &[(String, bool, bool)],
    diff_table: Option<&TrackedTableOracle<B>>,
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
        sign_gadget_names.len(),
        "Sort gadget expects name for each sign gadget."
    );

    for ((tie_idx, input_idx), rotated_idx) in tie_indices
        .iter()
        .copied()
        .zip(input_indices.iter().copied())
        .zip(rotated_indices.iter().copied())
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
        let sign_pos = sign_gadget_names
            .iter()
            .position(|name| name == &col_name)
            .unwrap_or_else(|| {
                panic!("Missing sign gadget for Sort column {}", col_name);
            });
        let sign_gadget = &sign_gadgets[sign_pos];
        // Mirror diff column typing in the verifier flow.
        let (diff_oracle, diff_field) = if let Some(diff_table) = diff_table {
            let diff_idx = diff_table
                .data_tracked_oracles_indices()
                .into_iter()
                .find(|idx| {
                    let diff_field = diff_table
                        .tracked_col_oracle_by_ind(*idx)
                        .field_ref()
                        .expect("Expected field ref for diff column");
                    normalize_sort_name(diff_field.name()) == col_name
                })
                .unwrap_or_else(|| panic!("Missing diff column for Sort column {}", col_name));
            let diff_col = diff_table.tracked_col_oracle_by_ind(diff_idx);
            let diff_field = diff_col
                .field_ref()
                .expect("Expected field ref for diff column")
                .as_ref()
                .clone();
            (diff_col.data_tracked_oracle(), diff_field)
        } else if is_asc {
            (
                &rotated_col.data_tracked_oracle() - &input_col.data_tracked_oracle(),
                input_col
                    .field_ref()
                    .expect("Expected field ref for Sort sign input")
                    .as_ref()
                    .clone(),
            )
        } else {
            (
                &input_col.data_tracked_oracle() - &rotated_col.data_tracked_oracle(),
                input_col
                    .field_ref()
                    .expect("Expected field ref for Sort sign input")
                    .as_ref()
                    .clone(),
            )
        };
        let data_field = Arc::new(diff_field);
        let input_activator = input_table.activator_tracked_poly();
        let rotated_activator = rotated_table.activator_tracked_poly();
        let mut combined_activator = tie_col.data_tracked_oracle();
        if let Some(input_act) = input_activator {
            combined_activator = &combined_activator * &input_act;
        }
        if let Some(rotated_act) = rotated_activator {
            combined_activator = &combined_activator * &rotated_act;
        }
        let sign_input = TrackedTableOracle::single_column_with_activator(
            data_field,
            diff_oracle,
            Some(combined_activator),
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

fn populate_neq_payloads_prover<B: SnarkBackend>(
    neq_gadgets: &[Arc<Node<B>>],
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
        "Sort neq gadget expects one tie indicator per data column."
    );
    debug_assert_eq!(
        input_indices.len(),
        rotated_indices.len(),
        "Sort neq gadget expects matching input and rotated column counts."
    );
    debug_assert_eq!(
        neq_gadgets.len(),
        input_indices.len().saturating_sub(1),
        "Sort gadget expects one neq gadget per adjacent data column."
    );

    for (((neq_gadget, tie_idx), tie_next_idx), (input_idx, rotated_idx)) in neq_gadgets
        .iter()
        .zip(tie_indices.iter().copied())
        .zip(tie_indices.iter().copied().skip(1))
        .zip(
            input_indices
                .iter()
                .copied()
                .zip(rotated_indices.iter().copied()),
        )
    {
        let tie_col = tie_table.tracked_col_by_ind(tie_idx);
        let tie_next_col = tie_table.tracked_col_by_ind(tie_next_idx);
        let one_poly = TrackedPoly::new(
            Either::Right(B::F::one()),
            tie_next_col.data_tracked_poly().log_size(),
            tie_next_col.data_tracked_poly().tracker(),
        );
        // Activate only when a tie breaks and the row is active.
        let mut activator =
            &tie_col.data_tracked_poly() * &(&one_poly - &tie_next_col.data_tracked_poly());
        if let Some(input_act) = input_table.activator_tracked_poly() {
            activator = &activator * &input_act;
        }
        if let Some(rotated_act) = rotated_table.activator_tracked_poly() {
            activator = &activator * &rotated_act;
        }

        let input_col = input_table.tracked_col_by_ind(input_idx);
        let rotated_col = rotated_table.tracked_col_by_ind(rotated_idx);
        let data_field = input_col
            .field_ref()
            .expect("Expected field ref for Sort neq input");
        let left_table = TrackedTable::single_column_with_activator(
            data_field.clone(),
            rotated_col.data_tracked_poly(),
            Some(activator.clone()),
        );
        let right_table = TrackedTable::single_column_with_activator(
            data_field,
            input_col.data_tracked_poly(),
            Some(activator),
        );

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
    }
    Ok(())
}

fn populate_neq_payloads_verifier<B: SnarkBackend>(
    neq_gadgets: &[Arc<Node<B>>],
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
        "Sort neq gadget expects one tie indicator per data column."
    );
    debug_assert_eq!(
        input_indices.len(),
        rotated_indices.len(),
        "Sort neq gadget expects matching input and rotated column counts."
    );
    debug_assert_eq!(
        neq_gadgets.len(),
        input_indices.len().saturating_sub(1),
        "Sort gadget expects one neq gadget per adjacent data column."
    );

    for (((neq_gadget, tie_idx), tie_next_idx), (input_idx, rotated_idx)) in neq_gadgets
        .iter()
        .zip(tie_indices.iter().copied())
        .zip(tie_indices.iter().copied().skip(1))
        .zip(
            input_indices
                .iter()
                .copied()
                .zip(rotated_indices.iter().copied()),
        )
    {
        let tie_col = tie_table.tracked_col_oracle_by_ind(tie_idx);
        let tie_next_col = tie_table.tracked_col_oracle_by_ind(tie_next_idx);
        let one_oracle = TrackedOracle::new(
            Either::Right(B::F::one()),
            tie_next_col.data_tracked_oracle().tracker(),
            tie_next_col.data_tracked_oracle().log_size(),
        );
        // Match prover activation logic for verifier oracles.
        let mut activator =
            &tie_col.data_tracked_oracle() * &(&one_oracle - &tie_next_col.data_tracked_oracle());
        if let Some(input_act) = input_table.activator_tracked_poly() {
            activator = &activator * &input_act;
        }
        if let Some(rotated_act) = rotated_table.activator_tracked_poly() {
            activator = &activator * &rotated_act;
        }

        let input_col = input_table.tracked_col_oracle_by_ind(input_idx);
        let rotated_col = rotated_table.tracked_col_oracle_by_ind(rotated_idx);
        let data_field = input_col
            .field_ref()
            .expect("Expected field ref for Sort neq input");
        let left_table = TrackedTableOracle::single_column_with_activator(
            data_field.clone(),
            rotated_col.data_tracked_oracle(),
            Some(activator.clone()),
        );
        let right_table = TrackedTableOracle::single_column_with_activator(
            data_field,
            input_col.data_tracked_oracle(),
            Some(activator),
        );

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

    let tie_indices = tie_table.data_tracked_polys_indices();
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

    let tie_indices = tie_table.data_tracked_oracles_indices();
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

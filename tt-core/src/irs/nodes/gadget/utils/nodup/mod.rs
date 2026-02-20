use std::{
    panic,
    sync::{Arc, Mutex},
};

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};
use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use ark_ff::BigInteger;
use ark_piop::{SnarkBackend, prover::ArgProver, verifier::ArgVerifier};
use datafusion::arrow::array::Array;
use indexmap::IndexMap;

pub const INPUT_LABEL: &str = "_input_";
pub const LEX_SORTED_LABEL: &str = "_lex_sorted_";
const PK_METADATA_KEY: &str = "tt.pk";
/// Prefix for the prover->verifier side channel that carries the number
/// of active input rows for SortNoDup.
const SORT_NODUP_ACTIVE_INPUT_ROWS_PREFIX: &str = "sort_nodup_active_input_rows";
type GadgetPayload<T> = IndexMap<String, T>;

mod bezout;
mod binary_check;
mod defragg;
mod hints;
mod keyed_sumcheck;
mod perm_check;
mod rematerialize_check;

pub enum Mode {
    BezoutBased,
    SortBased,
}
pub enum Gadgets<B: SnarkBackend> {
    BezoutNoDup,
    SortNoDup(SortNoDupGadgets<B>),
}

pub struct SortNoDupGadgets<B: SnarkBackend>(Arc<Node<B>>);

pub struct GadgetNode<B: SnarkBackend> {
    is_pk: Mutex<bool>,
    gadgets: Gadgets<B>,
    /// Cached during planning from the concrete input hint. Later phases can
    /// build a virtual contiguous activator without recollecting the input DF.
    sort_nodup_active_input_rows: Mutex<Option<usize>>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "NoDup".to_string()
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
        // Determine whether all data columns of the NoDup input are PK columns.
        // "Data columns" exclude system columns (activator/row_id).
        let is_pk = planned_ir
            .payload_for_node(&id)
            .and_then(|payload| match payload {
                PayloadStructure::GadgetPayload(payload) => payload.get(INPUT_LABEL),
                PayloadStructure::PlanPayload(_) => None,
            })
            .map(nodup_input_is_pk)
            .unwrap_or(false);
        self.cache_is_pk(is_pk);


        if self.is_pk() {
            // PK inputs are guaranteed to have no duplicates, so we can skip
            // adding any gadgets and checks in this case.
            return Ok(());
        }

        // SortNoDup is the only mode that uses planner hints/virtual witnesses.
        let Gadgets::SortNoDup(_) = &self.gadgets else {
            return Ok(());
        };
        let mut self_payload = gadget_payload_or_panic(
            id,
            planned_ir.payload_for_node(&id).cloned(),
            "No gadget payload found for NoDup gadget",
        );
        let input_hint =
            payload_value_or_panic(id, &self_payload, INPUT_LABEL, "No input hint found");
        self.cache_sort_nodup_active_rows(active_row_count_from_hint(&input_hint));
        let lex_sorted_hint = build_lex_sorted_hint(&input_hint);
        self_payload.insert(LEX_SORTED_LABEL.to_string(), lex_sorted_hint.clone());
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(self_payload)));

        // The child sort gadget should consume the same table as virtual data.
        // We intentionally keep activator virtual so prover/verifier can rebuild
        // it deterministically from active-row count.
        let lex_sorted_virtual_hint =
            crate::irs::nodes::hints::HintDF::new_virtual(lex_sorted_hint.data_frame().clone());
        let Gadgets::SortNoDup(gadgets) = &self.gadgets else {
            return Ok(());
        };
        let sort_id = gadgets.0.id();
        let sort_payload = with_sort_table_label(
            planned_ir.payload_for_node(&sort_id).cloned(),
            lex_sorted_virtual_hint,
        );
        planned_ir
            .set_payload_for_node(sort_id, Some(PayloadStructure::GadgetPayload(sort_payload)));
        Ok(())
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        if self.is_pk() {
            // PK inputs are guaranteed to have no duplicates, so we can skip
            // adding any gadgets and checks in this case.
            return vec![];
        }
        match &self.gadgets {
            Gadgets::BezoutNoDup => vec![],
            Gadgets::SortNoDup(g) => vec![g.0.clone()],
        }
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        if self.is_pk() {
            // PK inputs are guaranteed to have no duplicates, so we can skip
            // adding any gadgets and checks in this case.
            return Ok(());
        }
        let Gadgets::SortNoDup(_) = &self.gadgets else {
            return Ok(());
        };
        let Some(PayloadStructure::GadgetPayload(mut payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };
        let lex_sorted_table =
            payload_value_or_panic(id, &payload, LEX_SORTED_LABEL, "No lex sorted hint found");
        let num_active_input_rows = self.cached_sort_nodup_active_rows();
        let key = active_input_rows_misc_key(id, virtualized_ir.tree());
        let Some(tracker_rc) = lex_sorted_table
            .activator_tracked_poly()
            .map(|poly| poly.tracker())
            .or_else(|| {
                lex_sorted_table
                    .tracked_polys_iter()
                    .next()
                    .map(|(_, poly)| poly.tracker())
            })
        else {
            return Ok(());
        };
        tracker_rc
            .borrow_mut()
            .insert_miscellaneous_field(key, B::F::from(num_active_input_rows as u64));
        let contig_activator = tracker_rc
            .borrow_mut()
            .get_or_build_contig_one_poly(lex_sorted_table.log_size(), num_active_input_rows)?;
        let lex_sorted_with_activator =
            append_activator_prover(&lex_sorted_table, contig_activator);
        payload.insert(LEX_SORTED_LABEL.to_string(), lex_sorted_with_activator);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(payload)));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        if self.is_pk() {
            // PK inputs are guaranteed to have no duplicates, so we can skip
            // adding any gadgets and checks in this case.
            return Ok(());
        }
        let Gadgets::SortNoDup(gadgets) = &self.gadgets else {
            return Ok(());
        };
        let payload = gadget_payload_or_panic(
            id,
            virtualized_ir.payload_for_node(&id).cloned(),
            "No gadget payload found for NoDup gadget",
        );
        let lex_sorted_hint =
            payload_value_or_panic(id, &payload, LEX_SORTED_LABEL, "No lex sorted hint found");
        let sort_id = gadgets.0.id();
        let sort_payload = with_sort_table_label(
            virtualized_ir.payload_for_node(&sort_id).cloned(),
            lex_sorted_hint,
        );
        virtualized_ir
            .set_payload_for_node(sort_id, Some(PayloadStructure::GadgetPayload(sort_payload)));
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        if self.is_pk() {
            // PK inputs are guaranteed to have no duplicates, so we can skip
            // adding any gadgets and checks in this case.
            return Ok(());
        }
        let Gadgets::SortNoDup(_) = &self.gadgets else {
            return Ok(());
        };
        let mut payload = gadget_payload_or_panic(
            id,
            virtualized_ir.payload_for_node(&id).cloned(),
            "No gadget payload found for NoDup gadget",
        );
        let lex_sorted_table =
            payload_value_or_panic(id, &payload, LEX_SORTED_LABEL, "No lex sorted hint found");
        let key = active_input_rows_misc_key(id, virtualized_ir.tree());
        let Some(tracker_rc) = lex_sorted_table
            .activator_tracked_poly()
            .map(|oracle| oracle.tracker())
            .or_else(|| {
                lex_sorted_table
                    .tracked_oracles_iter()
                    .next()
                    .map(|(_, oracle)| oracle.tracker())
            })
        else {
            panic!(
                "No tracked oracle found in lex sorted hint for NoDup gadget at node {:?}",
                id
            );
        };
        let num_active_input_rows_field = tracker_rc.borrow().miscellaneous_field_element(&key)?;
        let num_active_input_rows = field_to_usize::<B::F>(num_active_input_rows_field)?;
        let contig_activator = tracker_rc
            .borrow_mut()
            .get_or_build_contig_one_oracle(lex_sorted_table.log_size(), num_active_input_rows)?;
        let lex_sorted_with_activator =
            append_activator_verifier(&lex_sorted_table, contig_activator);
        payload.insert(LEX_SORTED_LABEL.to_string(), lex_sorted_with_activator);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(payload)));
        Ok(())
    }
    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        if self.is_pk() {
            // PK inputs are guaranteed to have no duplicates, so we can skip
            // adding any gadgets and checks in this case.
            return Ok(());
        }
        let Gadgets::SortNoDup(gadgets) = &self.gadgets else {
            return Ok(());
        };
        let payload = gadget_payload_or_panic(
            id,
            virtualized_ir.payload_for_node(&id).cloned(),
            "No gadget payload found for NoDup gadget",
        );
        let lex_sorted_hint =
            payload_value_or_panic(id, &payload, LEX_SORTED_LABEL, "No lex sorted hint found");
        let sort_id = gadgets.0.id();
        let sort_payload = with_sort_table_label(
            virtualized_ir.payload_for_node(&sort_id).cloned(),
            lex_sorted_hint,
        );
        virtualized_ir
            .set_payload_for_node(sort_id, Some(PayloadStructure::GadgetPayload(sort_payload)));
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
        if self.is_pk() {
            // PK inputs are guaranteed to have no duplicates, so we can skip
            // adding any gadgets and checks in this case.
            return Ok(());
        }
        match self.gadgets {
            Gadgets::BezoutNoDup => Self::prove_nodup_bezout(prover, gadget_ready_ir, id),
            Gadgets::SortNoDup(_) => Ok(()),
        }
    }

    fn honest_prover_check(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        if self.is_pk() {
            // PK inputs are guaranteed to have no duplicates, so we can skip
            // adding any gadgets and checks in this case.
            return Ok(());
        }
        match self.gadgets {
            Gadgets::BezoutNoDup => Self::honest_check_no_dup_active(prover, gadget_ready_ir, id),
            // SortNoDup is enforced compositionally by its child gadgets
            // (sorting + permutation + keyed constraints), so we intentionally
            // skip the direct active-row duplicate scan in this path.
            Gadgets::SortNoDup(_) => Ok(()),
        }
    }

    fn verify(
        &self,
        verifier: &mut ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        if self.is_pk() {
            // PK inputs are guaranteed to have no duplicates, so we can skip
            // adding any gadgets and checks in this case.
            return Ok(());
        }
        match self.gadgets {
            Gadgets::BezoutNoDup => Self::verify_nodup_bezout(verifier, gadget_ready_ir, id),
            Gadgets::SortNoDup(_) => Ok(()),
        }
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> Default for GadgetNode<B> {
    fn default() -> Self {
        Self::new(Mode::SortBased)
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(mode: Mode) -> Self {
        match mode {
            Mode::BezoutBased => Self {
                is_pk: Mutex::new(false),
                gadgets: Gadgets::BezoutNoDup,
                sort_nodup_active_input_rows: Mutex::new(None),
            },
            Mode::SortBased => Self {
                is_pk: Mutex::new(false),
                gadgets: Gadgets::SortNoDup(SortNoDupGadgets(Arc::new(Node::<B>::Gadget(
                    Arc::new(
                        crate::irs::nodes::gadget::utils::contig_sort::GadgetNode::new_preserve_row_id(
                            crate::irs::nodes::gadget::utils::contig_sort::SortConfig::Uniform(
                                crate::irs::nodes::gadget::utils::contig_sort::UniformConfig {
                                    asc: false,
                                    strict: true,
                                },
                            ),
                        ),
                    ),
                )))),
                sort_nodup_active_input_rows: Mutex::new(None),
            },
        }
    }

    fn cache_is_pk(&self, is_pk: bool) {
        *self
            .is_pk
            .lock()
            .expect("NoDup pk lock should not be poisoned") = is_pk;
    }

    fn is_pk(&self) -> bool {
        *self
            .is_pk
            .lock()
            .expect("NoDup pk lock should not be poisoned")
    }

    fn cache_sort_nodup_active_rows(&self, rows: usize) {
        *self
            .sort_nodup_active_input_rows
            .lock()
            .expect("NoDup active-row lock should not be poisoned") = Some(rows);
    }

    fn cached_sort_nodup_active_rows(&self) -> usize {
        self.sort_nodup_active_input_rows
            .lock()
            .expect("NoDup active-row lock should not be poisoned")
            .as_ref()
            .copied()
            .expect("NoDup active-row count should be initialized in initialize_gadget_plans")
    }
}

fn build_lex_sorted_hint(
    input_hint: &crate::irs::nodes::hints::HintDF,
) -> crate::irs::nodes::hints::HintDF {
    let lex_sorted_df = hints::lex_sort_contiguous(input_hint.data_frame().clone())
        .expect("NoDup lex sort should succeed");
    let should_materialize = lex_sorted_df
        .schema()
        .fields()
        .iter()
        .map(|field| {
            (
                field.clone(),
                field.name() != ROW_ID_COL_NAME && field.name() != ACTIVATOR_COL_NAME,
            )
        })
        .collect();
    crate::irs::nodes::hints::HintDF::new(lex_sorted_df, should_materialize)
}

fn with_sort_table_label<T>(payload: Option<PayloadStructure<T>>, table: T) -> GadgetPayload<T> {
    let mut payload = gadget_payload_or_empty(payload);
    payload.insert(
        crate::irs::nodes::gadget::utils::contig_sort::TABLE_LABEL.to_string(),
        table,
    );
    payload
}

fn gadget_payload_or_empty<T>(payload: Option<PayloadStructure<T>>) -> GadgetPayload<T> {
    match payload {
        Some(PayloadStructure::GadgetPayload(payload)) => payload,
        Some(PayloadStructure::PlanPayload(_)) | None => IndexMap::new(),
    }
}

fn gadget_payload_or_panic<T>(
    id: crate::irs::nodes::NodeId,
    payload: Option<PayloadStructure<T>>,
    context: &str,
) -> GadgetPayload<T> {
    match payload {
        Some(PayloadStructure::GadgetPayload(payload)) => payload,
        Some(PayloadStructure::PlanPayload(_)) | None => panic!("{context} at node {:?}", id),
    }
}

fn payload_value_or_panic<T: Clone>(
    id: crate::irs::nodes::NodeId,
    payload: &GadgetPayload<T>,
    label: &str,
    context: &str,
) -> T {
    payload
        .get(label)
        .unwrap_or_else(|| panic!("{context} for label '{label}' at node {:?}", id))
        .clone()
}

fn nodup_input_is_pk(input_hint: &crate::irs::nodes::hints::HintDF) -> bool {
    let data_fields: Vec<_> = input_hint
        .data_frame()
        .schema()
        .fields()
        .iter()
        .filter(|field| field.name() != ACTIVATOR_COL_NAME && field.name() != ROW_ID_COL_NAME)
        .collect();
    if data_fields.is_empty() {
        return false;
    }
    data_fields.into_iter().all(|field| {
        field
            .metadata()
            .get(PK_METADATA_KEY)
            .map(|value| matches!(value.to_ascii_lowercase().as_str(), "true" | "1" | "yes"))
            .unwrap_or(false)
    })
}

/// Count active rows in a hint. If no activator exists, all rows are active.
fn active_row_count_from_hint(hint: &crate::irs::nodes::hints::HintDF) -> usize {
    let batches = collect_blocking(hint.data_frame().clone())
        .expect("NoDup input-hint collection should succeed");
    let has_activator = hint
        .data_frame()
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ACTIVATOR_COL_NAME);
    if !has_activator {
        return batches.iter().map(|batch| batch.num_rows()).sum();
    }
    batches
        .into_iter()
        .map(|batch| {
            let activator_idx = batch
                .schema()
                .fields()
                .iter()
                .position(|field| field.name() == ACTIVATOR_COL_NAME)
                .expect("NoDup input batch missing activator column");
            let activator = batch
                .column(activator_idx)
                .as_any()
                .downcast_ref::<datafusion::arrow::array::BooleanArray>()
                .expect("NoDup activator column should be boolean");
            (0..activator.len())
                .filter(|&i| activator.is_valid(i) && activator.value(i))
                .count()
        })
        .sum()
}

fn active_input_rows_misc_key<B: SnarkBackend>(
    target_id: crate::irs::nodes::NodeId,
    tree: &crate::irs::tree::Tree<B>,
) -> String {
    // We intentionally do NOT key by raw NodeId. Prover and verifier build
    // separate trees and pointer-derived ids may differ across runs.
    // DFS rank among NoDup nodes stays deterministic across both trees.
    fn dfs_rank<B: SnarkBackend>(
        node: &Arc<Node<B>>,
        target_id: crate::irs::nodes::NodeId,
        rank: &mut usize,
        found: &mut Option<usize>,
    ) {
        if found.is_some() {
            return;
        }

        let is_nodup = matches!(node.as_ref(), Node::Gadget(_)) && node.name() == "NoDup";
        if is_nodup {
            if node.id() == target_id {
                *found = Some(*rank);
                return;
            }
            *rank += 1;
        }

        for child in node.children() {
            dfs_rank(&child, target_id, rank, found);
            if found.is_some() {
                return;
            }
        }
    }

    let mut rank = 0usize;
    let mut found = None;
    dfs_rank(tree.root(), target_id, &mut rank, &mut found);
    let nodup_rank = found.unwrap_or_else(|| {
        panic!(
            "NoDup node id {:?} was not found while computing misc key",
            target_id
        )
    });
    format!("{SORT_NODUP_ACTIVE_INPUT_ROWS_PREFIX}_{nodup_rank}")
}

fn append_activator_prover<B: SnarkBackend>(
    table: &arithmetic::table::TrackedTable<B>,
    activator: ark_piop::prover::structs::polynomial::TrackedPoly<B>,
) -> arithmetic::table::TrackedTable<B> {
    let mut polys = table.tracked_polys();
    let activator_field = polys
        .keys()
        .find(|field| field.name() == ACTIVATOR_COL_NAME)
        .cloned()
        .unwrap_or_else(|| arithmetic::ACTIVATOR_FIELD.clone());
    polys.insert(activator_field, activator);
    let schema = table.schema_ref().map(|schema| {
        let fields = polys
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        datafusion::arrow::datatypes::Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    arithmetic::table::TrackedTable::new(schema, polys, table.log_size())
}

fn append_activator_verifier<B: SnarkBackend>(
    table: &arithmetic::table_oracle::TrackedTableOracle<B>,
    activator: ark_piop::verifier::structs::oracle::TrackedOracle<B>,
) -> arithmetic::table_oracle::TrackedTableOracle<B> {
    let mut oracles = table.tracked_oracles();
    let activator_field = oracles
        .keys()
        .find(|field| field.name() == ACTIVATOR_COL_NAME)
        .cloned()
        .unwrap_or_else(|| arithmetic::ACTIVATOR_FIELD.clone());
    oracles.insert(activator_field, activator);
    let schema = table.schema_ref().map(|schema| {
        let fields = oracles
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        datafusion::arrow::datatypes::Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    arithmetic::table_oracle::TrackedTableOracle::new(schema, oracles, table.log_size())
}

fn field_to_usize<F: ark_ff::PrimeField>(value: F) -> ark_piop::errors::SnarkResult<usize> {
    let big = value.into_bigint();
    let bytes = big.to_bytes_le();
    let mut out: usize = 0;
    let max = std::mem::size_of::<usize>();
    for (i, byte) in bytes.iter().enumerate() {
        if i >= max {
            if *byte != 0u8 {
                return Err(ark_piop::errors::SnarkError::VerifierError(
                    ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(
                        "nodup contig n does not fit into usize".to_string(),
                    ),
                ));
            }
            continue;
        }
        out |= (*byte as usize) << (8 * i);
    }
    Ok(out)
}

fn collect_blocking(
    df: datafusion::prelude::DataFrame,
) -> datafusion_common::Result<Vec<datafusion::arrow::record_batch::RecordBatch>> {
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
                        .map_err(|e| {
                            datafusion_common::DataFusionError::Execution(e.to_string())
                        })?;
                    rt.block_on(df_clone.collect())
                })
                .join()
                .map_err(|_| {
                    datafusion_common::DataFusionError::Execution(
                        "dataframe collection thread panicked".to_string(),
                    )
                })?
            }
            _ => tokio::task::block_in_place(|| handle.block_on(df.collect())),
        },
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| datafusion_common::DataFusionError::Execution(e.to_string()))?;
            rt.block_on(df.collect())
        }
    }
}

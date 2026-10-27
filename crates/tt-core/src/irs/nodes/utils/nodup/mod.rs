use crate::irs::nodes::utils::{
    SnarkError, VerifierError, commit_with_tracker, field_to_usize, track_next_committed,
};
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
use arithmetic::{
    ACTIVATOR_COL_NAME, ROW_ID_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_piop::{SnarkBackend, prover::ArgProver, verifier::ArgVerifier};
use datafusion::arrow::array::Array;

use crate::irs::nodes::utils::contig_sort::{ACTIVE_ROWS_LABEL, active_rows_field};
use indexmap::IndexMap;

pub const INPUT_LABEL: &str = "_input_";
pub const LEX_SORTED_LABEL: &str = "_lex_sorted_";
const PK_METADATA_KEY: &str = "tt.pk";
/// Prefix for the prover->verifier side channel that carries the number
/// of active input rows for SortNoDup.
type GadgetPayload<T> = IndexMap<String, T>;

mod bezout;
mod binary_check;
mod compaction_check;
mod compactor;
pub(crate) mod perm_check;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    BezoutBased,
    SortBased,
}
pub enum Gadgets<B: SnarkBackend> {
    BezoutNoDup,
    SortNoDup(SortNoDupGadgets<B>),
}

pub struct SortNoDupGadgets<B: SnarkBackend> {
    sort_gadget: Arc<Node<B>>,
    perm_gadget: Arc<Node<B>>,
}

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

    fn children(&self) -> Vec<Arc<Node<B>>> {
        if self.is_pk() {
            // PK inputs are guaranteed to have no duplicates: no gadgets and
            // no checks, here and in every phase below.
            return vec![];
        }
        match &self.gadgets {
            Gadgets::BezoutNoDup => vec![],
            Gadgets::SortNoDup(g) => vec![g.perm_gadget.clone(), g.sort_gadget.clone()],
        }
    }
}

fn initialize_gadget_plans<B: SnarkBackend>(
    node: &GadgetNode<B>,
    id: crate::irs::nodes::NodeId,
    planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    is_verifier: bool,
) -> ark_piop::errors::SnarkResult<()> {
    let mut self_payload = match planned_ir.payload_for_node(&id).cloned() {
        Some(PayloadStructure::GadgetPayload(payload)) => payload,
        _ => {
            panic!("No payload found for NoDup gadget at node {:?}", id);
        }
    };
    let Some(input_hint) = self_payload.get(INPUT_LABEL).cloned() else {
        panic!("No input hint found for NoDup gadget at node {:?}", id);
    };
    let is_pk = nodup_input_is_pk(&input_hint);
    node.cache_is_pk(is_pk);
    if is_pk {
        return Ok(());
    }

    // SortNoDup is the only mode that uses planner hints/virtual witnesses.
    let Gadgets::SortNoDup(_) = &node.gadgets else {
        return Ok(());
    };
    if !is_verifier {
        node.cache_sort_nodup_active_rows(active_row_count_from_hint(&input_hint));
    } else {
        // Verifier planning should avoid eager DataFrame collection here.
        node.cache_sort_nodup_active_rows(0);
    }
    let lex_sorted_hint = if is_verifier {
        build_lex_sorted_hint_for_verifier(&input_hint)
    } else {
        build_lex_sorted_hint::<B>(&input_hint)?
    };
    self_payload.insert(LEX_SORTED_LABEL.to_string(), lex_sorted_hint.clone());
    planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(self_payload)));

    // The child sort gadget consumes the same table as virtual data. The
    // activator stays virtual so that prover and verifier rebuild it from the
    // active-row count.
    let lex_sorted_virtual_hint = lex_sorted_hint.as_virtual_view();
    let Gadgets::SortNoDup(gadgets) = &node.gadgets else {
        return Ok(());
    };
    let sort_id = gadgets.sort_gadget.id();
    let sort_payload = with_sort_table_label(
        planned_ir.payload_for_node(&sort_id).cloned(),
        lex_sorted_virtual_hint,
        None,
    );
    planned_ir.set_payload_for_node(sort_id, Some(PayloadStructure::GadgetPayload(sort_payload)));

    let perm_payload = with_perm_payload(
        planned_ir
            .payload_for_node(&gadgets.perm_gadget.id())
            .cloned(),
        input_hint.as_virtual_view(),
        lex_sorted_hint.as_virtual_view(),
    );
    planned_ir.set_payload_for_node(
        gadgets.perm_gadget.id(),
        Some(PayloadStructure::GadgetPayload(perm_payload)),
    );
    Ok(())
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
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        if self.is_pk() {
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
        // The count fixes the public activator `C_{µ,n}`; committing it binds
        // it to the transcript before any challenge.
        let count = commit_with_tracker(
            &tracker_rc,
            0,
            vec![B::F::from(num_active_input_rows as u64)],
        )?;
        let contig_activator = tracker_rc
            .borrow_mut()
            .get_or_build_contig_one_poly(lex_sorted_table.log_size(), num_active_input_rows)?;
        let lex_sorted_with_activator =
            append_activator_prover(&lex_sorted_table, contig_activator);
        payload.insert(LEX_SORTED_LABEL.to_string(), lex_sorted_with_activator);
        payload.insert(
            ACTIVE_ROWS_LABEL.to_string(),
            TrackedTable::single_column_with_activator(active_rows_field(), count, None),
        );
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
            return Ok(());
        }
        let Gadgets::SortNoDup(gadgets) = &self.gadgets else {
            return Ok(());
        };
        let payload = match virtualized_ir.payload_for_node(&id).cloned() {
            Some(PayloadStructure::GadgetPayload(payload)) => payload,
            Some(PayloadStructure::PlanPayload(_)) | None => {
                panic!("No gadget payload found for NoDup gadget at node {:?}", id)
            }
        };
        let lex_sorted_hint =
            payload_value_or_panic(id, &payload, LEX_SORTED_LABEL, "No lex sorted hint found");
        let sort_id = gadgets.sort_gadget.id();
        let sort_payload = with_sort_table_label(
            virtualized_ir.payload_for_node(&sort_id).cloned(),
            lex_sorted_hint.clone(),
            payload.get(ACTIVE_ROWS_LABEL).cloned(),
        );
        virtualized_ir
            .set_payload_for_node(sort_id, Some(PayloadStructure::GadgetPayload(sort_payload)));

        let input_table =
            payload_value_or_panic(id, &payload, INPUT_LABEL, "No input table found for NoDup");
        let perm_payload = with_perm_payload(
            virtualized_ir
                .payload_for_node(&gadgets.perm_gadget.id())
                .cloned(),
            input_table,
            lex_sorted_hint,
        );
        virtualized_ir.set_payload_for_node(
            gadgets.perm_gadget.id(),
            Some(PayloadStructure::GadgetPayload(perm_payload)),
        );
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
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        if self.is_pk() {
            return Ok(());
        }
        let Gadgets::SortNoDup(_) = &self.gadgets else {
            return Ok(());
        };
        let mut payload = match virtualized_ir.payload_for_node(&id).cloned() {
            Some(PayloadStructure::GadgetPayload(payload)) => payload,
            _ => return Ok(()),
        };
        let Some(lex_sorted_table) = payload.get(LEX_SORTED_LABEL) else {
            return Ok(());
        };
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
        let count = track_next_committed(&tracker_rc)?;
        let num_active_input_rows = match count.as_constant() {
            Some(value) if count.log_size() == 0 => field_to_usize(value, "nodup contig n")?,
            _ => {
                return Err(SnarkError::VerifierError(
                    VerifierError::VerifierCheckFailed(
                        "the NoDup row count is not a committed scalar".to_string(),
                    ),
                ));
            }
        };
        let contig_activator = tracker_rc
            .borrow_mut()
            .get_or_build_contig_one_poly(lex_sorted_table.log_size(), num_active_input_rows)?;
        let lex_sorted_with_activator =
            append_activator_verifier(lex_sorted_table, contig_activator);
        payload.insert(LEX_SORTED_LABEL.to_string(), lex_sorted_with_activator);
        payload.insert(
            ACTIVE_ROWS_LABEL.to_string(),
            TrackedTableOracle::single_column_with_activator(active_rows_field(), count, None),
        );
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
            return Ok(());
        }
        let Gadgets::SortNoDup(gadgets) = &self.gadgets else {
            return Ok(());
        };
        let payload = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(payload)) => payload,
            _ => return Ok(()),
        };
        let Some(lex_sorted_hint) = payload.get(LEX_SORTED_LABEL).cloned() else {
            return Ok(());
        };
        let Some(input_table) = payload.get(INPUT_LABEL).cloned() else {
            return Ok(());
        };
        let sort_id = gadgets.sort_gadget.id();
        let sort_payload = with_sort_table_label(
            virtualized_ir.payload_for_node(&sort_id).cloned(),
            lex_sorted_hint.clone(),
            payload.get(ACTIVE_ROWS_LABEL).cloned(),
        );
        virtualized_ir
            .set_payload_for_node(sort_id, Some(PayloadStructure::GadgetPayload(sort_payload)));
        let perm_payload = with_perm_payload(
            virtualized_ir
                .payload_for_node(&gadgets.perm_gadget.id())
                .cloned(),
            input_table,
            lex_sorted_hint,
        );
        virtualized_ir.set_payload_for_node(
            gadgets.perm_gadget.id(),
            Some(PayloadStructure::GadgetPayload(perm_payload)),
        );
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
        Self::honest_check_no_dup_active(prover, gadget_ready_ir, id)
    }

    fn verify(
        &self,
        verifier: &mut ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        if self.is_pk() {
            return Ok(());
        }
        match self.gadgets {
            Gadgets::BezoutNoDup => Self::verify_nodup_bezout(verifier, gadget_ready_ir, id),
            Gadgets::SortNoDup(_) => Ok(()),
        }
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
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
                gadgets: Gadgets::SortNoDup(SortNoDupGadgets {
                    sort_gadget: Arc::new(Node::<B>::Gadget(Arc::new(
                        crate::irs::nodes::utils::contig_sort::GadgetNode::new_preserve_row_id(
                            crate::irs::nodes::utils::contig_sort::SortConfig::Distinct,
                        ),
                    ))),
                    perm_gadget: Arc::new(Node::<B>::Gadget(Arc::new(
                        crate::irs::nodes::utils::perm::GadgetNode::new(),
                    ))),
                }),
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

/// The input sorted in the order the distinct sort check proves.
fn build_lex_sorted_hint<B: SnarkBackend>(
    input_hint: &crate::irs::nodes::hints::HintDF,
) -> ark_piop::errors::SnarkResult<crate::irs::nodes::hints::HintDF> {
    let lex_sorted_df = crate::irs::nodes::utils::contig_sort::sort_distinct::<B::F>(
        input_hint.data_frame().clone(),
    )
    .map_err(|e| ark_piop::errors::SnarkError::Artifact(format!("NoDup sort: {e}")))?;
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
    Ok(crate::irs::nodes::hints::HintDF::new(
        lex_sorted_df,
        should_materialize,
    ))
}

fn build_lex_sorted_hint_for_verifier(
    input_hint: &crate::irs::nodes::hints::HintDF,
) -> crate::irs::nodes::hints::HintDF {
    // Verifier planning only needs schema + materialization flags. Avoid
    // lex-sort/window planning work here.
    let should_materialize = input_hint
        .data_frame()
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
    crate::irs::nodes::hints::HintDF::new_assume_normalized(
        input_hint.data_frame().clone(),
        should_materialize,
    )
}

/// The sort check's payload: the sorted table, and once witnesses exist `n`,
/// as the table's activator is `C_{µ,n}`.
fn with_sort_table_label<T>(
    payload: Option<PayloadStructure<T>>,
    table: T,
    active_rows: Option<T>,
) -> GadgetPayload<T> {
    let mut payload = gadget_payload_or_empty(payload);
    payload.insert(
        crate::irs::nodes::utils::contig_sort::TABLE_LABEL.to_string(),
        table,
    );
    if let Some(count) = active_rows {
        payload.insert(ACTIVE_ROWS_LABEL.to_string(), count);
    }
    payload
}

fn with_perm_payload<T>(
    payload: Option<PayloadStructure<T>>,
    left: T,
    right: T,
) -> GadgetPayload<T> {
    let mut payload = gadget_payload_or_empty(payload);
    payload.insert(crate::irs::nodes::utils::perm::LEFT_LABEL.to_string(), left);
    payload.insert(
        crate::irs::nodes::utils::perm::RIGHT_LABEL.to_string(),
        right,
    );
    payload
}

fn gadget_payload_or_empty<T>(payload: Option<PayloadStructure<T>>) -> GadgetPayload<T> {
    match payload {
        Some(PayloadStructure::GadgetPayload(payload)) => payload,
        Some(PayloadStructure::PlanPayload(_)) | None => IndexMap::new(),
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

/// Without an activator column, all rows are active.
fn active_row_count_from_hint(hint: &crate::irs::nodes::hints::HintDF) -> usize {
    let batches = crate::session::block_on(hint.data_frame().clone().collect())
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

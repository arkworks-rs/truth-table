use std::sync::Arc;

use crate::irs::{
    nodes::{
        IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps, gadget::utils::prescr_perm,
    },
    payloads::PayloadStructure,
};
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;
use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::arithmetic::mat_poly::mle::MLE;
use ark_piop::prover::structs::polynomial::TrackedPoly;
use ark_piop::verifier::structs::oracle::TrackedOracle;
use ark_piop::{SnarkBackend, piop::PIOP};
use col_toolbox::lookup::{LookupPIOP, LookupProverInput, LookupVerifierInput};
use datafusion::arrow::{
    array::RecordBatch,
    datatypes::{DataType, Field, FieldRef, Schema},
};
use datafusion_common::{DataFusionError, Result as DataFusionResult};
use datafusion_expr::{Expr, Join};
use either::Either;
use indexmap::IndexMap;
use std::cell::RefCell;
use std::sync::RwLock;

const QUALIFIER_METADATA_KEY: &str = "tt.qualifier";
mod hints;
mod wiring;
pub const LEFT_LABEL: &str = "__LEFT__";
pub const RIGHT_LABEL: &str = "__RIGHT__";
pub const OUTPUT_LABEL: &str = "__OUTPUT__";
pub const SRC_LEFT_LABEL: &str = "__SRC_LEFT__";
pub const SRC_RIGHT_LABEL: &str = "__SRC_RIGHT__";
pub const SRC_LEFT_COL_NAME: &str = "src_left";
pub const SRC_RIGHT_COL_NAME: &str = "src_right";
pub use crate::irs::nodes::plan::lps::join::modes::JoinMode;

#[derive(Clone)]
struct JoinPlanningDerivedHints {
    left_hint: crate::irs::nodes::hints::HintDF,
    right_hint: crate::irs::nodes::hints::HintDF,
    output_hint: crate::irs::nodes::hints::HintDF,
    src_left_hint: crate::irs::nodes::hints::HintDF,
    src_right_hint: crate::irs::nodes::hints::HintDF,
    nodup_input_hint: crate::irs::nodes::hints::HintDF,
}

thread_local! {
    static JOIN_PLANNING_CACHE: RefCell<Option<IndexMap<crate::irs::nodes::NodeId, JoinPlanningDerivedHints>>> =
        const { RefCell::new(None) };
}

pub fn begin_join_planning_cache_scope() {
    JOIN_PLANNING_CACHE.with(|cache| {
        *cache.borrow_mut() = Some(IndexMap::new());
    });
}

pub fn end_join_planning_cache_scope() {
    JOIN_PLANNING_CACHE.with(|cache| {
        *cache.borrow_mut() = None;
    });
}

fn derive_many_to_many_hints(
    join: &Join,
    left_hint: &crate::irs::nodes::hints::HintDF,
    right_hint: &crate::irs::nodes::hints::HintDF,
    output_hint: &crate::irs::nodes::hints::HintDF,
) -> JoinPlanningDerivedHints {
    let left_hint = force_materialize_all(&force_materialize_row_id(left_hint));
    let right_hint = force_materialize_all(&force_materialize_row_id(right_hint));
    let output_hint = force_materialize_all(output_hint);

    let left_df = left_hint.data_frame().clone();
    let right_df = right_hint.data_frame().clone();
    let output_df = output_hint.data_frame().clone();

    let (left_src_df, right_src_df) =
        hints::build_source_dfs(left_df.clone(), right_df.clone(), output_df.clone(), join)
            .expect("join source dataframe derivation should succeed");
    let nodup_input_df = hints::build_nodup_input_df(left_df, right_df, output_df, join)
        .expect("join nodup dataframe derivation should succeed");

    JoinPlanningDerivedHints {
        left_hint,
        right_hint,
        output_hint,
        src_left_hint: crate::irs::nodes::hints::HintDF::new_materialized(left_src_df),
        src_right_hint: crate::irs::nodes::hints::HintDF::new_materialized(right_src_df),
        nodup_input_hint: crate::irs::nodes::hints::HintDF::new_materialized(nodup_input_df),
    }
}

fn get_or_build_many_to_many_hints(
    id: crate::irs::nodes::NodeId,
    join: &Join,
    left_hint: &crate::irs::nodes::hints::HintDF,
    right_hint: &crate::irs::nodes::hints::HintDF,
    output_hint: &crate::irs::nodes::hints::HintDF,
) -> JoinPlanningDerivedHints {
    JOIN_PLANNING_CACHE.with(|cache| {
        let mut guard = cache.borrow_mut();
        if let Some(scope_cache) = guard.as_mut() {
            if let Some(cached) = scope_cache.get(&id) {
                return cached.clone();
            }
            let derived = derive_many_to_many_hints(join, left_hint, right_hint, output_hint);
            scope_cache.insert(id, derived.clone());
            return derived;
        }
        derive_many_to_many_hints(join, left_hint, right_hint, output_hint)
    })
}

fn force_materialize_row_id(
    hint: &crate::irs::nodes::hints::HintDF,
) -> crate::irs::nodes::hints::HintDF {
    let row_id_already_materialized = hint
        .field_materialization_iter()
        .find(|(field, _)| field.name() == arithmetic::ROW_ID_COL_NAME)
        .is_none_or(|(_, materialized)| *materialized);
    if row_id_already_materialized {
        return hint.clone();
    }

    // Source-row mapping reconstructs provenance from concrete row ids, so row_id
    // must be materialized even when the original hint marks it virtual.
    let mut should_materialize = hint
        .field_materialization_iter()
        .map(|(field, materialized)| {
            (
                field.clone(),
                if field.name() == arithmetic::ROW_ID_COL_NAME {
                    true
                } else {
                    *materialized
                },
            )
        })
        .collect::<IndexMap<_, _>>();
    // Preserve shape even if the hint unexpectedly lacks row-id.
    if should_materialize.is_empty() {
        should_materialize = IndexMap::new();
    }
    crate::irs::nodes::hints::HintDF::new(hint.data_frame().clone(), should_materialize)
}

fn force_materialize_all(
    hint: &crate::irs::nodes::hints::HintDF,
) -> crate::irs::nodes::hints::HintDF {
    // Fast path: avoid rebuilding the map if all fields are already materialized.
    if hint
        .field_materialization_iter()
        .all(|(_, materialized)| *materialized)
    {
        return hint.clone();
    }

    // The source-row hint builder replays the join in DataFusion, so it needs the
    // full concrete left/right/output rows (including activators) at this stage.
    let should_materialize = hint
        .field_materialization_iter()
        .map(|(field, _)| (field.clone(), true))
        .collect::<IndexMap<_, _>>();
    crate::irs::nodes::hints::HintDF::new(hint.data_frame().clone(), should_materialize)
}

pub enum Gadgets<B: SnarkBackend> {
    // Full join proof stack: bool + nodup + match-pair utilities.
    ManyToMany(ManyToManyGadgets<B>),
    // Optimized mode for joins where one side is guaranteed unique.
    // No child gadgets are needed.
    HasOne,
}
pub struct ManyToManyGadgets<B: SnarkBackend> {
    pub(super) bool_gadget: Arc<Node<B>>,
    pub(super) nodup_gadget: Arc<Node<B>>,
    pub(super) match_pair_gadget: Arc<Node<B>>,
}
pub struct GadgetNode<B: SnarkBackend> {
    gadgets: RwLock<Gadgets<B>>,
    join: Join,
    join_mode: RwLock<JoinMode>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Join".to_string()
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
        if let Some(gadgets) = self.many_to_many_gadgets() {
            vec![
                gadgets.bool_gadget.clone(),
                gadgets.nodup_gadget.clone(),
                gadgets.match_pair_gadget.clone(),
            ]
        } else {
            vec![]
        }
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        if let Some(gadgets) = self.many_to_many_gadgets() {
            let mut gadget_payload = match planned_ir.payload_for_node(&id) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => return Ok(()),
            };
            let left_hint = match gadget_payload.get(LEFT_LABEL) {
                Some(hint_df) => hint_df,
                None => return Ok(()),
            };
            let right_hint = match gadget_payload.get(RIGHT_LABEL) {
                Some(hint_df) => hint_df,
                None => return Ok(()),
            };
            let output_hint = match gadget_payload.get(OUTPUT_LABEL) {
                Some(hint_df) => hint_df,
                None => return Ok(()),
            };
            let derived = get_or_build_many_to_many_hints(
                id,
                &self.join,
                left_hint,
                right_hint,
                output_hint,
            );
            let JoinPlanningDerivedHints {
                left_hint,
                right_hint,
                output_hint,
                src_left_hint,
                src_right_hint,
                nodup_input_hint,
            } = derived;
            // Overwrite with the concretized hints so later join-subgadgets (and
            // provenance checks) see the same materialized inputs used to derive
            // source-row hints.
            gadget_payload.insert(LEFT_LABEL.to_string(), left_hint);
            gadget_payload.insert(RIGHT_LABEL.to_string(), right_hint);
            gadget_payload.insert(OUTPUT_LABEL.to_string(), output_hint);
            gadget_payload.insert(SRC_LEFT_LABEL.to_string(), src_left_hint);
            gadget_payload.insert(SRC_RIGHT_LABEL.to_string(), src_right_hint);
            planned_ir
                .set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));

            let mut nodup_payload = match planned_ir.payload_for_node(&gadgets.nodup_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            nodup_payload.insert(
                crate::irs::nodes::gadget::utils::nodup::INPUT_LABEL.to_string(),
                nodup_input_hint,
            );
            planned_ir.set_payload_for_node(
                gadgets.nodup_gadget.id(),
                Some(PayloadStructure::GadgetPayload(nodup_payload)),
            );
            Ok(())
        } else {
            Ok(())
        }
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
        if self.many_to_many_gadgets().is_some() {
            // First fetch the payload for the current node, prepared by the parent
            let Some(PayloadStructure::GadgetPayload(payload)) =
                virtualized_ir.payload_for_node(&id).cloned()
            else {
                panic!("Expected gadget payload for Join gadget node")
            };
            // Among the payload, we expect left, right, and output tables
            let current_output = payload
                .get(OUTPUT_LABEL)
                .unwrap_or_else(|| panic!("Join gadget payload missing {OUTPUT_LABEL}"));
            let current_left = payload
                .get(LEFT_LABEL)
                .unwrap_or_else(|| panic!("Join gadget payload missing {LEFT_LABEL}"));
            let current_right = payload
                .get(RIGHT_LABEL)
                .unwrap_or_else(|| panic!("Join gadget payload missing {RIGHT_LABEL}"));
            let current_left_src = payload
                .get(SRC_LEFT_LABEL)
                .unwrap_or_else(|| panic!("Join gadget payload missing {SRC_LEFT_LABEL}"));
            let current_right_src = payload
                .get(SRC_RIGHT_LABEL)
                .unwrap_or_else(|| panic!("Join gadget payload missing {SRC_RIGHT_LABEL}"));
            self.wire_prover_bool_payload(current_output, virtualized_ir);

            self.wire_prover_nodup_payload(
                current_output,
                current_left_src,
                current_right_src,
                virtualized_ir,
            );

            self.wire_prover_match_pair_payload(
                current_output,
                current_left,
                current_right,
                virtualized_ir,
            );
            Ok(())
        } else {
            Ok(())
        }
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        if let Some(gadgets) = self.many_to_many_gadgets() {
            let mut gadget_payload = match planned_ir.payload_for_node(&id) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => return Ok(()),
            };
            let derived = {
                let Some(left_hint) = gadget_payload.get(LEFT_LABEL) else {
                    return Ok(());
                };
                let Some(right_hint) = gadget_payload.get(RIGHT_LABEL) else {
                    return Ok(());
                };
                let Some(output_hint) = gadget_payload.get(OUTPUT_LABEL) else {
                    return Ok(());
                };
                derive_many_to_many_hints_verifier(left_hint, right_hint, output_hint)
            };

            let JoinPlanningDerivedHints {
                left_hint,
                right_hint,
                output_hint,
                src_left_hint,
                src_right_hint,
                nodup_input_hint,
            } = derived;
            gadget_payload.insert(LEFT_LABEL.to_string(), left_hint);
            gadget_payload.insert(RIGHT_LABEL.to_string(), right_hint);
            gadget_payload.insert(OUTPUT_LABEL.to_string(), output_hint);
            gadget_payload.insert(SRC_LEFT_LABEL.to_string(), src_left_hint);
            gadget_payload.insert(SRC_RIGHT_LABEL.to_string(), src_right_hint);
            planned_ir
                .set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));

            let mut nodup_payload = match planned_ir.payload_for_node(&gadgets.nodup_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            nodup_payload.insert(
                crate::irs::nodes::gadget::utils::nodup::INPUT_LABEL.to_string(),
                nodup_input_hint,
            );
            planned_ir.set_payload_for_node(
                gadgets.nodup_gadget.id(),
                Some(PayloadStructure::GadgetPayload(nodup_payload)),
            );
            Ok(())
        } else {
            Ok(())
        }
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
        if self.many_to_many_gadgets().is_some() {
            let (current_output, current_left, current_right, current_left_src, current_right_src) = {
                let Some(PayloadStructure::GadgetPayload(payload)) =
                    virtualized_ir.payload_for_node(&id)
                else {
                    panic!("expected gadget payload for Join gadget node")
                };
                (
                    payload
                        .get(OUTPUT_LABEL)
                        .unwrap_or_else(|| panic!("Join gadget payload missing {OUTPUT_LABEL}"))
                        .clone(),
                    payload
                        .get(LEFT_LABEL)
                        .unwrap_or_else(|| panic!("Join gadget payload missing {LEFT_LABEL}"))
                        .clone(),
                    payload
                        .get(RIGHT_LABEL)
                        .unwrap_or_else(|| panic!("Join gadget payload missing {RIGHT_LABEL}"))
                        .clone(),
                    payload
                        .get(SRC_LEFT_LABEL)
                        .unwrap_or_else(|| panic!("Join gadget payload missing {SRC_LEFT_LABEL}"))
                        .clone(),
                    payload
                        .get(SRC_RIGHT_LABEL)
                        .unwrap_or_else(|| panic!("Join gadget payload missing {SRC_RIGHT_LABEL}"))
                        .clone(),
                )
            };
            self.wire_verifier_bool_payload(&current_output, virtualized_ir);

            self.wire_verifier_nodup_payload(
                &current_output,
                &current_left_src,
                &current_right_src,
                virtualized_ir,
            );

            self.wire_verifier_match_pair_payload(
                &current_output,
                &current_left,
                &current_right,
                virtualized_ir,
            );
            Ok(())
        } else {
            Ok(())
        }
    }
}

fn derive_many_to_many_hints_verifier(
    left_hint: &crate::irs::nodes::hints::HintDF,
    right_hint: &crate::irs::nodes::hints::HintDF,
    output_hint: &crate::irs::nodes::hints::HintDF,
) -> JoinPlanningDerivedHints {
    // Verifier join planning only needs fully materialized schemas; forcing all
    // columns materialized already implies row_id materialization.
    let left_hint = force_materialize_all(left_hint);
    let right_hint = force_materialize_all(right_hint);
    let output_hint = force_materialize_all(output_hint);

    let left_row_id_ty = left_hint
        .data_frame()
        .schema()
        .fields()
        .iter()
        .find(|f| f.name() == arithmetic::ROW_ID_COL_NAME)
        .map(|f| f.data_type().clone())
        .unwrap_or(DataType::Int64);
    let right_row_id_ty = right_hint
        .data_frame()
        .schema()
        .fields()
        .iter()
        .find(|f| f.name() == arithmetic::ROW_ID_COL_NAME)
        .map(|f| f.data_type().clone())
        .unwrap_or(DataType::Int64);
    let output_row_id_ty = output_hint
        .data_frame()
        .schema()
        .fields()
        .iter()
        .find(|f| f.name() == arithmetic::ROW_ID_COL_NAME)
        .map(|f| f.data_type().clone())
        .unwrap_or(DataType::Int64);

    let src_left_schema = Arc::new(Schema::new(vec![
        Field::new(SRC_LEFT_COL_NAME, left_row_id_ty.clone(), true),
        Field::new(arithmetic::ACTIVATOR_COL_NAME, DataType::Boolean, true),
        Field::new(arithmetic::ROW_ID_COL_NAME, output_row_id_ty.clone(), true),
    ]));
    let src_right_schema = Arc::new(Schema::new(vec![
        Field::new(SRC_RIGHT_COL_NAME, right_row_id_ty.clone(), true),
        Field::new(arithmetic::ACTIVATOR_COL_NAME, DataType::Boolean, true),
        Field::new(arithmetic::ROW_ID_COL_NAME, output_row_id_ty.clone(), true),
    ]));
    let nodup_schema = Arc::new(Schema::new(vec![
        Field::new(SRC_LEFT_COL_NAME, left_row_id_ty, true),
        Field::new(SRC_RIGHT_COL_NAME, right_row_id_ty, true),
        Field::new(arithmetic::ACTIVATOR_COL_NAME, DataType::Boolean, true),
        Field::new(arithmetic::ROW_ID_COL_NAME, output_row_id_ty, true),
    ]));

    let src_left_df = crate::irs::nodes::hints::schema_only_df(
        src_left_schema
            .fields()
            .iter()
            .map(|f| f.as_ref().clone())
            .collect(),
    );
    let src_right_df = crate::irs::nodes::hints::schema_only_df(
        src_right_schema
            .fields()
            .iter()
            .map(|f| f.as_ref().clone())
            .collect(),
    );
    let nodup_df = crate::irs::nodes::hints::schema_only_df(
        nodup_schema
            .fields()
            .iter()
            .map(|f| f.as_ref().clone())
            .collect(),
    );

    JoinPlanningDerivedHints {
        left_hint,
        right_hint,
        output_hint,
        src_left_hint: crate::irs::nodes::hints::HintDF::new_materialized(src_left_df),
        src_right_hint: crate::irs::nodes::hints::HintDF::new_materialized(src_right_df),
        nodup_input_hint: crate::irs::nodes::hints::HintDF::new_materialized(nodup_df),
    }
}

fn folding_challenges<F: PrimeField>(count: usize) -> Vec<F> {
    (0..count).map(|i| F::from((i + 1) as u64)).collect()
}

fn single_data_col_from_table<B: SnarkBackend>(
    table: &TrackedTable<B>,
    label: &str,
) -> (FieldRef, TrackedPoly<B>) {
    let data_indices = table.data_tracked_polys_indices();
    if data_indices.len() != 1 {
        panic!("Join {label} table must have exactly one data column");
    }
    let data_cols = table.tracked_polys();
    let (field, poly) = data_cols
        .get_index(data_indices[0])
        .expect("Join src data column missing");
    (field.clone(), poly.clone())
}

fn index_tracked_poly<B: SnarkBackend>(
    prover: &mut ark_piop::prover::ArgProver<B>,
    table: &TrackedTable<B>,
) -> TrackedPoly<B> {
    if let Some(row_id_col) = table.tracked_col_by_name(arithmetic::ROW_ID_COL_NAME) {
        return row_id_col.data_tracked_poly();
    }
    let log_size = table.log_size();
    let index_mle = MLE::from_evaluations_vec(
        log_size,
        (0..(1 << log_size)).map(|i| B::F::from(i as u64)).collect(),
    );
    prover.track_mat_mv_poly(index_mle)
}

fn append_tracked_col<B: SnarkBackend>(
    table: &TrackedTable<B>,
    field: FieldRef,
    poly: TrackedPoly<B>,
) -> TrackedTable<B> {
    let mut tracked_polys = table.tracked_polys();
    tracked_polys.insert(field.clone(), poly);
    let schema = table.schema_ref().map(|schema| {
        let mut fields = schema
            .fields()
            .iter()
            .map(|f| f.as_ref().clone())
            .collect::<Vec<_>>();
        fields.push(field.as_ref().clone());
        Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    let schema = schema.or_else(|| {
        Some(Schema::new(
            tracked_polys
                .keys()
                .map(|f| f.as_ref().clone())
                .collect::<Vec<_>>(),
        ))
    });
    TrackedTable::new(schema, tracked_polys, table.log_size())
}

fn append_tracked_oracle<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    field: FieldRef,
    oracle: TrackedOracle<B>,
) -> TrackedTableOracle<B> {
    let mut tracked_oracles = table.tracked_oracles();
    tracked_oracles.insert(field.clone(), oracle);
    let schema = table.schema_ref().map(|schema| {
        let mut fields = schema
            .fields()
            .iter()
            .map(|f| f.as_ref().clone())
            .collect::<Vec<_>>();
        fields.push(field.as_ref().clone());
        Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    let schema = schema.or_else(|| {
        Some(Schema::new(
            tracked_oracles
                .keys()
                .map(|f| f.as_ref().clone())
                .collect::<Vec<_>>(),
        ))
    });
    TrackedTableOracle::new(schema, tracked_oracles, table.log_size())
}

fn single_data_col_from_table_oracle<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    label: &str,
) -> (FieldRef, TrackedOracle<B>) {
    let data_indices = table.data_tracked_oracles_indices();
    if data_indices.len() != 1 {
        panic!("Join {label} table must have exactly one data column");
    }
    let data_cols = table.tracked_oracles();
    let (field, oracle) = data_cols
        .get_index(data_indices[0])
        .expect("Join src data column missing");
    (field.clone(), oracle.clone())
}

fn index_tracked_oracle<B: SnarkBackend>(
    _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
    table: &TrackedTableOracle<B>,
) -> TrackedOracle<B> {
    if let Some(row_id_col) = table.tracked_col_oracle_by_name(arithmetic::ROW_ID_COL_NAME) {
        return row_id_col.data_tracked_oracle();
    }
    let data_col = table
        .data_tracked_oracles_indices()
        .first()
        .copied()
        .map(|idx| table.tracked_col_oracle_by_ind(idx))
        .unwrap_or_else(|| panic!("Join expects data columns on left table"));
    let log_size = data_col.data_tracked_oracle().log_size();
    let index_oracle = prescr_perm::shift_permutation_oracle::<B::F>(log_size, 0, true);
    let tracker = data_col.data_tracked_oracle().tracker();
    let index_id = tracker.borrow_mut().track_oracle(index_oracle);
    TrackedOracle::new(Either::Left(index_id), tracker, log_size)
}

fn output_base_from_output<B: SnarkBackend>(
    output: &TrackedTable<B>,
    left: &TrackedTable<B>,
) -> TrackedTable<B> {
    let output_cols = output.tracked_polys();
    let left_fields: Vec<FieldRef> = match left.schema_ref() {
        Some(schema) => schema
            .fields()
            .iter()
            .map(|field| Arc::new(field.as_ref().clone()))
            .collect(),
        None => left.tracked_polys().keys().cloned().collect(),
    };

    // Keep the same column order as `left` so folding challenges are aligned
    // between output-derived rows and input rows in lookup checks.
    let mut filtered = IndexMap::new();
    for left_field in left_fields.iter() {
        // Keep the activator for provenance lookups so padded rows stay inactive
        // after folding. We only drop row_id because we append the source/index
        // column separately.
        if left_field.name() == arithmetic::ROW_ID_COL_NAME {
            continue;
        }
        if let Some((out_field, out_poly)) = output_cols
            .iter()
            .find(|(out_field, _)| field_matches(left_field, out_field))
        {
            filtered.insert(out_field.clone(), out_poly.clone());
        }
    }

    let metadata = left
        .schema_ref()
        .map(|schema| schema.metadata().clone())
        .unwrap_or_default();
    let fields: Vec<Field> = filtered
        .keys()
        .map(|field| field.as_ref().clone())
        .collect();
    let schema = Some(Schema::new_with_metadata(fields, metadata));
    TrackedTable::new(schema, filtered, output.log_size())
}

fn input_base_from_output<B: SnarkBackend>(
    input: &TrackedTable<B>,
    output: &TrackedTable<B>,
) -> TrackedTable<B> {
    let output_cols = output.tracked_polys();
    let input_cols = input.tracked_polys();
    let mut filtered = IndexMap::new();
    for (field, poly) in input_cols.iter() {
        // Keep the activator for the same reason as output_base_from_output().
        if field.name() == arithmetic::ROW_ID_COL_NAME {
            continue;
        }
        if !output_cols
            .keys()
            .any(|out_field| field_matches(field, out_field))
        {
            continue;
        }
        filtered.insert(field.clone(), poly.clone());
    }
    let metadata = input
        .schema_ref()
        .map(|schema| schema.metadata().clone())
        .unwrap_or_default();
    let fields: Vec<Field> = filtered
        .keys()
        .map(|field| field.as_ref().clone())
        .collect();
    let schema = Some(Schema::new_with_metadata(fields, metadata));
    TrackedTable::new(schema, filtered, input.log_size())
}

fn output_base_from_output_oracle<B: SnarkBackend>(
    output: &TrackedTableOracle<B>,
    left: &TrackedTableOracle<B>,
) -> TrackedTableOracle<B> {
    let output_cols = output.tracked_oracles();
    let left_fields: Vec<FieldRef> = match left.schema_ref() {
        Some(schema) => schema
            .fields()
            .iter()
            .map(|field| Arc::new(field.as_ref().clone()))
            .collect(),
        None => left.tracked_oracles().keys().cloned().collect(),
    };

    // Mirror prover ordering for deterministic folding alignment.
    let mut filtered = IndexMap::new();
    for left_field in left_fields.iter() {
        // Mirror prover behavior: keep activator, exclude only row_id.
        if left_field.name() == arithmetic::ROW_ID_COL_NAME {
            continue;
        }
        if let Some((out_field, out_oracle)) = output_cols
            .iter()
            .find(|(out_field, _)| field_matches(left_field, out_field))
        {
            filtered.insert(out_field.clone(), out_oracle.clone());
        }
    }

    let metadata = left
        .schema_ref()
        .map(|schema| schema.metadata().clone())
        .unwrap_or_default();
    let fields: Vec<Field> = filtered
        .keys()
        .map(|field| field.as_ref().clone())
        .collect();
    let schema = Some(Schema::new_with_metadata(fields, metadata));
    TrackedTableOracle::new(schema, filtered, output.log_size())
}

fn input_base_from_output_oracle<B: SnarkBackend>(
    input: &TrackedTableOracle<B>,
    output: &TrackedTableOracle<B>,
) -> TrackedTableOracle<B> {
    let output_cols = output.tracked_oracles();
    let input_cols = input.tracked_oracles();
    let mut filtered = IndexMap::new();
    for (field, oracle) in input_cols.iter() {
        // Mirror prover behavior: keep activator, exclude only row_id.
        if field.name() == arithmetic::ROW_ID_COL_NAME {
            continue;
        }
        if !output_cols
            .keys()
            .any(|out_field| field_matches(field, out_field))
        {
            continue;
        }
        filtered.insert(field.clone(), oracle.clone());
    }
    let metadata = input
        .schema_ref()
        .map(|schema| schema.metadata().clone())
        .unwrap_or_default();
    let fields: Vec<Field> = filtered
        .keys()
        .map(|field| field.as_ref().clone())
        .collect();
    let schema = Some(Schema::new_with_metadata(fields, metadata));
    TrackedTableOracle::new(schema, filtered, input.log_size())
}

fn field_matches(left: &FieldRef, right: &FieldRef) -> bool {
    if left.name() != right.name() {
        return false;
    }
    if left.name() == arithmetic::ACTIVATOR_COL_NAME || left.name() == arithmetic::ROW_ID_COL_NAME {
        return true;
    }
    // Use qualifier metadata to disambiguate when left/right share column names.
    let left_qual = field_qualifier(left);
    let right_qual = field_qualifier(right);
    match (left_qual, right_qual) {
        (Some(l), Some(r)) => l == r,
        (None, None) => true,
        _ => false,
    }
}

fn field_qualifier(field: &FieldRef) -> Option<&str> {
    field
        .metadata()
        .get(QUALIFIER_METADATA_KEY)
        .map(|value| value.as_str())
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        if self.many_to_many_gadgets().is_some() {
            let Some(PayloadStructure::GadgetPayload(payload)) =
                gadget_ready_ir.payload_for_node(&id)
            else {
                panic!("Expected gadget payload for Join gadget node");
            };

            let Some(output) = payload.get(OUTPUT_LABEL).cloned() else {
                panic!("Expected output table for Join gadget");
            };
            let Some(left_table) = payload.get(LEFT_LABEL).cloned() else {
                panic!("Expected left table for Join gadget");
            };
            let Some(right_table) = payload.get(RIGHT_LABEL).cloned() else {
                panic!("Expected right table for Join gadget");
            };
            let Some(left_src) = payload.get(SRC_LEFT_LABEL).cloned() else {
                panic!("Expected src-left table for Join gadget");
            };
            let Some(right_src) = payload.get(SRC_RIGHT_LABEL).cloned() else {
                panic!("Expected src-right table for Join gadget");
            };

            // Purpose: Every row in the output table must consist of columns that come from some row in the left table.
            // Method: We look up table output_left in input_left
            // output left = [output activator | output keys + Output data coming from the left table + their source row number from the left table]
            // input left = [left activator | left keys + left data + normal index]
            let (src_field, src_poly) = single_data_col_from_table(&left_src, "src-left");
            let output_left_base = output_base_from_output(&output, &left_table);
            let output_left = append_tracked_col(&output_left_base, src_field.clone(), src_poly);

            let index_poly = index_tracked_poly(prover, &left_table);
            let input_left_base = input_base_from_output(&left_table, &output);
            let input_left = append_tracked_col(&input_left_base, src_field, index_poly);

            let output_challs = folding_challenges::<B::F>(output_left.num_data_tracked_cols());
            let output_folded = output_left.fold_all_data_columns(&output_challs);
            let input_challs = folding_challenges::<B::F>(input_left.num_data_tracked_cols());
            let input_folded = input_left.fold_all_data_columns(&input_challs);

            // Use activator-aware lookup so empty joins / padded rows do not
            // create false provenance claims.
            LookupPIOP::<B>::prove(
                prover,
                LookupProverInput {
                    included_cols: vec![output_folded],
                    super_col: input_folded,
                },
            )?;

            // Purpose: Every row in the output table must consist of columns that come from some row in the right table.
            // Method: We look up table output_right in input_right
            // output right = [output activator | output keys + Output data coming from the right table + their source row number from the right table]
            // input right = [right activator | right keys + right data + normal index]

            let (right_src_field, right_src_poly) =
                single_data_col_from_table(&right_src, "src-right");
            let output_right_base = output_base_from_output(&output, &right_table);
            let output_right =
                append_tracked_col(&output_right_base, right_src_field.clone(), right_src_poly);

            let right_index_poly = index_tracked_poly(prover, &right_table);
            let input_right_base = input_base_from_output(&right_table, &output);
            let input_right =
                append_tracked_col(&input_right_base, right_src_field, right_index_poly);

            let output_right_challs =
                folding_challenges::<B::F>(output_right.num_data_tracked_cols());
            let output_right_folded = output_right.fold_all_data_columns(&output_right_challs);
            let input_right_challs =
                folding_challenges::<B::F>(input_right.num_data_tracked_cols());
            let input_right_folded = input_right.fold_all_data_columns(&input_right_challs);
            LookupPIOP::<B>::prove(
                prover,
                LookupProverInput {
                    included_cols: vec![output_right_folded],
                    super_col: input_right_folded,
                },
            )?;
            Ok(())
        } else {
            Ok(())
        }
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
        if self.many_to_many_gadgets().is_some() {
            let Some(PayloadStructure::GadgetPayload(payload)) =
                gadget_ready_ir.payload_for_node(&id)
            else {
                panic!("Expected gadget payload for Join gadget node");
            };

            let Some(output) = payload.get(OUTPUT_LABEL).cloned() else {
                panic!("Expected output table for Join gadget");
            };
            let Some(left_table) = payload.get(LEFT_LABEL).cloned() else {
                panic!("Expected left table for Join gadget");
            };
            let Some(right_table) = payload.get(RIGHT_LABEL).cloned() else {
                panic!("Expected right table for Join gadget");
            };
            let Some(left_src) = payload.get(SRC_LEFT_LABEL).cloned() else {
                panic!("Expected src-left table for Join gadget");
            };
            let Some(right_src) = payload.get(SRC_RIGHT_LABEL).cloned() else {
                panic!("Expected src-right table for Join gadget");
            };

            let (src_field, src_oracle) = single_data_col_from_table_oracle(&left_src, "src-left");
            let output_left_base = output_base_from_output_oracle(&output, &left_table);
            let output_left =
                append_tracked_oracle(&output_left_base, src_field.clone(), src_oracle);

            let index_oracle = index_tracked_oracle(verifier, &left_table);
            let input_left_base = input_base_from_output_oracle(&left_table, &output);
            let input_left = append_tracked_oracle(&input_left_base, src_field, index_oracle);

            let output_challs =
                folding_challenges::<B::F>(output_left.num_data_tracked_col_oracles());
            let output_folded = output_left.fold_all_data_oracles(&output_challs);
            let input_challs =
                folding_challenges::<B::F>(input_left.num_data_tracked_col_oracles());
            let input_folded = input_left.fold_all_data_oracles(&input_challs);

            LookupPIOP::<B>::verify(
                verifier,
                LookupVerifierInput {
                    included_tracked_col_oracles: vec![output_folded],
                    super_tracked_col_oracle: input_folded,
                },
            )?;

            let (right_src_field, right_src_oracle) =
                single_data_col_from_table_oracle(&right_src, "src-right");
            let output_right_base = output_base_from_output_oracle(&output, &right_table);
            let output_right = append_tracked_oracle(
                &output_right_base,
                right_src_field.clone(),
                right_src_oracle,
            );

            let right_index_oracle = index_tracked_oracle(verifier, &right_table);
            let input_right_base = input_base_from_output_oracle(&right_table, &output);
            let input_right =
                append_tracked_oracle(&input_right_base, right_src_field, right_index_oracle);

            let output_right_challs =
                folding_challenges::<B::F>(output_right.num_data_tracked_col_oracles());
            let output_right_folded = output_right.fold_all_data_oracles(&output_right_challs);
            let input_right_challs =
                folding_challenges::<B::F>(input_right.num_data_tracked_col_oracles());
            let input_right_folded = input_right.fold_all_data_oracles(&input_right_challs);

            LookupPIOP::<B>::verify(
                verifier,
                LookupVerifierInput {
                    included_tracked_col_oracles: vec![output_right_folded],
                    super_tracked_col_oracle: input_right_folded,
                },
            )?;
            Ok(())
        } else {
            Ok(())
        }
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(join: Join, join_mode: JoinMode) -> Self {
        let bool_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::bool::GadgetNode::new(),
        )));
        let nodup_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::nodup::GadgetNode::default(),
        )));
        let match_pair_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::match_pair_check::GadgetNode::new(),
        )));
        let mut gadgets = Gadgets::ManyToMany(ManyToManyGadgets {
            bool_gadget,
            nodup_gadget,
            match_pair_gadget,
        });
        // HasOne modes collapse join gadget internals to keep plan/gadget optimization aligned.
        if join_mode != JoinMode::MANY_TO_MANY {
            gadgets = Gadgets::HasOne;
        }
        Self {
            gadgets: RwLock::new(gadgets),
            join,
            join_mode: RwLock::new(join_mode),
        }
    }

    pub(super) fn many_to_many_gadgets(&self) -> Option<ManyToManyGadgets<B>> {
        if self.join_mode() != JoinMode::MANY_TO_MANY {
            return None;
        }
        let gadgets_guard = self.gadgets.read().ok()?;
        match &*gadgets_guard {
            Gadgets::ManyToMany(gadgets) => Some(ManyToManyGadgets {
                bool_gadget: gadgets.bool_gadget.clone(),
                nodup_gadget: gadgets.nodup_gadget.clone(),
                match_pair_gadget: gadgets.match_pair_gadget.clone(),
            }),
            Gadgets::HasOne => None,
        }
    }

    pub fn join_mode(&self) -> JoinMode {
        self.join_mode
            .read()
            .map(|mode| *mode)
            .unwrap_or(JoinMode::MANY_TO_MANY)
    }

    pub fn set_join_mode(&self, mode: JoinMode) {
        if let Ok(mut guard) = self.join_mode.write() {
            *guard = mode;
        }
        if let Ok(mut gadgets) = self.gadgets.write() {
            // Never rebuild MANY_TO_MANY children here: creating fresh child nodes would
            // change node ids and break IR payload maps keyed by existing ids.
            // Optimized modes collapse the join gadget into a no-op (no child gadgets).
            if mode != JoinMode::MANY_TO_MANY {
                *gadgets = Gadgets::HasOne;
            }
        }
    }
}

fn build_match_pair_hints(
    join: &datafusion_expr::Join,
    left_hint: &crate::irs::nodes::hints::HintDF,
    right_hint: &crate::irs::nodes::hints::HintDF,
    output_hint: &crate::irs::nodes::hints::HintDF,
) -> DataFusionResult<(
    crate::irs::nodes::hints::HintDF,
    crate::irs::nodes::hints::HintDF,
    crate::irs::nodes::hints::HintDF,
)> {
    let mut left_exprs: Vec<Expr> = join.on.iter().map(|(l, _)| l.clone()).collect();
    let mut right_exprs: Vec<Expr> = join.on.iter().map(|(_, r)| r.clone()).collect();
    crate::irs::nodes::hints::append_row_id_expr_if_present(
        left_hint.data_frame(),
        &mut left_exprs,
    );
    crate::irs::nodes::hints::append_activator_exprs_if_present(
        left_hint.data_frame(),
        &mut left_exprs,
    );
    crate::irs::nodes::hints::append_row_id_expr_if_present(
        right_hint.data_frame(),
        &mut right_exprs,
    );
    crate::irs::nodes::hints::append_activator_exprs_if_present(
        right_hint.data_frame(),
        &mut right_exprs,
    );

    let left_df = left_hint.data_frame().clone().select(left_exprs)?;
    let left_df = crate::irs::nodes::hints::sort_by_row_id_if_present(left_df)?;
    let right_df = right_hint.data_frame().clone().select(right_exprs)?;
    let right_df = crate::irs::nodes::hints::sort_by_row_id_if_present(right_df)?;

    let output_sorted =
        crate::irs::nodes::hints::sort_by_row_id_if_present(output_hint.data_frame().clone())?;
    let mut out_exprs = Vec::new();
    crate::irs::nodes::hints::append_activator_exprs_if_present(&output_sorted, &mut out_exprs);
    if out_exprs.is_empty() {
        return Err(DataFusionError::Plan(
            "Join output is missing an activator column".to_string(),
        ));
    }
    let output_df = output_sorted.select(out_exprs)?;

    Ok((
        crate::irs::nodes::hints::HintDF::new_virtual(left_df),
        crate::irs::nodes::hints::HintDF::new_virtual(right_df),
        crate::irs::nodes::hints::HintDF::new_virtual(output_df),
    ))
}

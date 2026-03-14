use std::sync::Arc;

use crate::irs::{
    nodes::{
        IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps, gadget::utils::prescr_perm,
    },
    payloads::PayloadStructure,
};
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;
use arithmetic::{
    col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_piop::arithmetic::mat_poly::mle::MLE;
use ark_piop::prover::structs::polynomial::TrackedPoly;
use ark_piop::verifier::structs::oracle::TrackedOracle;
use ark_piop::{SnarkBackend, piop::PIOP};
use col_toolbox::lookup::{LookupPIOP, LookupProverInput, LookupVerifierInput};
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use datafusion::prelude::lit;
use datafusion_expr::Join;
use either::Either;
use indexmap::IndexMap;
use std::cell::RefCell;
use std::sync::RwLock;

mod hints;
mod wiring;
pub const LEFT_LABEL: &str = "__LEFT__";
pub const RIGHT_LABEL: &str = "__RIGHT__";
pub const OUTPUT_LABEL: &str = "__OUTPUT__";
pub const OUTPUT_LEFT_LABEL: &str = "__OUTPUT_LEFT__";
pub const OUTPUT_RIGHT_LABEL: &str = "__OUTPUT_RIGHT__";
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
    output_left_hint: crate::irs::nodes::hints::HintDF,
    output_right_hint: crate::irs::nodes::hints::HintDF,
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
    let output_hint = force_materialize_all(&force_materialize_row_id(output_hint));

    let left_df = left_hint.data_frame().clone();
    let right_df = right_hint.data_frame().clone();
    let (output_left_df, output_right_df, left_src_df, right_src_df, nodup_input_df) =
        hints::build_output_and_source_dfs(left_df, right_df, join)
            .expect("join output/source dataframe derivation should succeed");

    JoinPlanningDerivedHints {
        left_hint,
        right_hint,
        output_hint,
        output_left_hint: crate::irs::nodes::hints::HintDF::new_materialized(output_left_df),
        output_right_hint: crate::irs::nodes::hints::HintDF::new_materialized(output_right_df),
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
            let derived =
                get_or_build_many_to_many_hints(id, &self.join, left_hint, right_hint, output_hint);
            let JoinPlanningDerivedHints {
                left_hint,
                right_hint,
                output_hint,
                output_left_hint: _output_left_hint,
                output_right_hint: _output_right_hint,
                src_left_hint,
                src_right_hint,
                nodup_input_hint,
            } = derived;
            // Overwrite with the concretized hints so later join-subgadgets (and
            // provenance checks) see the same materialized inputs used to derive
            // source-row hints.
            gadget_payload.insert(LEFT_LABEL.to_string(), left_hint.clone());
            gadget_payload.insert(RIGHT_LABEL.to_string(), right_hint.clone());
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

            let mut match_pair_payload =
                match planned_ir.payload_for_node(&gadgets.match_pair_gadget.id()) {
                    Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                    _ => IndexMap::new(),
                };
            // Parent gadget-planning runs pre-order, so seed the child with the
            // concretized join-side hints before Match-Pair plans its own children.
            match_pair_payload.insert(
                crate::irs::nodes::gadget::utils::match_pair_check::LEFT_LABEL.to_string(),
                left_hint.clone(),
            );
            match_pair_payload.insert(
                crate::irs::nodes::gadget::utils::match_pair_check::RIGHT_LABEL.to_string(),
                right_hint.clone(),
            );
            planned_ir.set_payload_for_node(
                gadgets.match_pair_gadget.id(),
                Some(PayloadStructure::GadgetPayload(match_pair_payload)),
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
                derive_many_to_many_hints_verifier(&self.join, left_hint, right_hint, output_hint)
            };

            let JoinPlanningDerivedHints {
                left_hint,
                right_hint,
                output_hint,
                output_left_hint: _output_left_hint,
                output_right_hint: _output_right_hint,
                src_left_hint,
                src_right_hint,
                nodup_input_hint,
            } = derived;
            gadget_payload.insert(LEFT_LABEL.to_string(), left_hint.clone());
            gadget_payload.insert(RIGHT_LABEL.to_string(), right_hint.clone());
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

            let mut match_pair_payload =
                match planned_ir.payload_for_node(&gadgets.match_pair_gadget.id()) {
                    Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                    _ => IndexMap::new(),
                };
            // Mirror prover-side planning so the Match-Pair child never needs to
            // reconstruct its left/right inputs by reaching back into the parent.
            match_pair_payload.insert(
                crate::irs::nodes::gadget::utils::match_pair_check::LEFT_LABEL.to_string(),
                left_hint.clone(),
            );
            match_pair_payload.insert(
                crate::irs::nodes::gadget::utils::match_pair_check::RIGHT_LABEL.to_string(),
                right_hint.clone(),
            );
            planned_ir.set_payload_for_node(
                gadgets.match_pair_gadget.id(),
                Some(PayloadStructure::GadgetPayload(match_pair_payload)),
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
    join: &Join,
    left_hint: &crate::irs::nodes::hints::HintDF,
    right_hint: &crate::irs::nodes::hints::HintDF,
    output_hint: &crate::irs::nodes::hints::HintDF,
) -> JoinPlanningDerivedHints {
    // The verifier must derive the same helper tables as the prover here; the
    // earlier schema-only approximation drifted tracker IDs on nested joins.
    let left_hint = force_materialize_all(&force_materialize_row_id(left_hint));
    let right_hint = force_materialize_all(&force_materialize_row_id(right_hint));
    let output_hint = force_materialize_all(&force_materialize_row_id(output_hint));

    let left_df = left_hint.data_frame().clone();
    let right_df = right_hint.data_frame().clone();
    let (_output_left_df, _output_right_df, src_left_df, src_right_df, nodup_df) =
        hints::build_output_and_source_dfs(left_df, right_df, join)
            .expect("join verifier output/source dataframe derivation should succeed");

    JoinPlanningDerivedHints {
        output_left_hint: build_verifier_output_side_hint(&left_hint, SRC_LEFT_COL_NAME),
        output_right_hint: build_verifier_output_side_hint(&right_hint, SRC_RIGHT_COL_NAME),
        left_hint,
        right_hint,
        output_hint,
        src_left_hint: crate::irs::nodes::hints::HintDF::new_materialized(src_left_df),
        src_right_hint: crate::irs::nodes::hints::HintDF::new_materialized(src_right_df),
        nodup_input_hint: crate::irs::nodes::hints::HintDF::new_materialized(nodup_df),
    }
}

fn build_verifier_output_side_hint(
    base_hint: &crate::irs::nodes::hints::HintDF,
    src_col_name: &str,
) -> crate::irs::nodes::hints::HintDF {
    // Keep the output-side lookup shape aligned with the prover without adding
    // extra tracked payload entries that the verifier would have to transfer.
    let mut exprs = base_hint
        .data_frame()
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            (field.name() != arithmetic::ROW_ID_COL_NAME).then_some(datafusion_expr::Expr::Column(
                datafusion_common::Column::new(qualifier.cloned(), field.name()),
            ))
        })
        .collect::<Vec<_>>();
    exprs.push(lit(0_i64).alias(src_col_name));
    let df = base_hint
        .data_frame()
        .clone()
        .select(exprs)
        .expect("verifier join output-side projection should succeed");
    crate::irs::nodes::hints::HintDF::new_materialized(df)
}

fn lookup_fold_challenges_prover<B: SnarkBackend>(
    prover: &mut ark_piop::prover::ArgProver<B>,
    width: usize,
) -> ark_piop::errors::SnarkResult<Vec<B::F>> {
    // The included and super tables for one lookup must share the same fold
    // challenges; otherwise the verifier compares different linear combinations.
    let mut challenges = Vec::with_capacity(width);
    for _ in 0..width {
        challenges.push(prover.get_and_append_challenge(b"lookup_fold")?);
    }
    Ok(challenges)
}

fn fold_lookup_table_prover<B: SnarkBackend>(
    table: &TrackedTable<B>,
    challenges: &[B::F],
) -> TrackedCol<B> {
    let data_indices = table.data_tracked_polys_indices();
    if data_indices.len() == 1 {
        return table.tracked_col_by_ind(data_indices[0]);
    }
    table.fold_all_data_columns(challenges)
}

fn lookup_fold_challenges_verifier<B: SnarkBackend>(
    verifier: &mut ark_piop::verifier::ArgVerifier<B>,
    width: usize,
) -> ark_piop::errors::SnarkResult<Vec<B::F>> {
    let mut challenges = Vec::with_capacity(width);
    for _ in 0..width {
        challenges.push(verifier.get_and_append_challenge(b"lookup_fold")?);
    }
    Ok(challenges)
}

fn fold_lookup_table_verifier<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    challenges: &[B::F],
) -> TrackedColOracle<B> {
    let data_indices = table.data_tracked_oracles_indices();
    if data_indices.len() == 1 {
        return table.tracked_col_oracle_by_ind(data_indices[0]);
    }
    table.fold_all_data_oracles(challenges)
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

fn input_lookup_base_from_table<B: SnarkBackend>(table: &TrackedTable<B>) -> TrackedTable<B> {
    let cols = table.tracked_polys();
    let fields: Vec<FieldRef> = match table.schema_ref() {
        Some(schema) => schema
            .fields()
            .iter()
            .map(|field| Arc::new(field.as_ref().clone()))
            .collect(),
        None => cols.keys().cloned().collect(),
    };
    let mut filtered = IndexMap::new();
    for field in fields {
        if field.name() == arithmetic::ROW_ID_COL_NAME {
            continue;
        }
        let poly = cols
            .get(&field)
            .unwrap_or_else(|| panic!("Join input table missing column {}", field.name()));
        filtered.insert(field, poly.clone());
    }
    let metadata = table
        .schema_ref()
        .map(|schema| schema.metadata().clone())
        .unwrap_or_default();
    let fields: Vec<Field> = filtered
        .keys()
        .map(|field| field.as_ref().clone())
        .collect();
    let schema = Some(Schema::new_with_metadata(fields, metadata));
    TrackedTable::new(schema, filtered, table.log_size())
}

fn input_lookup_base_from_table_oracle<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
) -> TrackedTableOracle<B> {
    let cols = table.tracked_oracles();
    let fields: Vec<FieldRef> = match table.schema_ref() {
        Some(schema) => schema
            .fields()
            .iter()
            .map(|field| Arc::new(field.as_ref().clone()))
            .collect(),
        None => cols.keys().cloned().collect(),
    };
    let mut filtered = IndexMap::new();
    for field in fields {
        if field.name() == arithmetic::ROW_ID_COL_NAME {
            continue;
        }
        let oracle = cols
            .get(&field)
            .unwrap_or_else(|| panic!("Join input table missing column {}", field.name()));
        filtered.insert(field, oracle.clone());
    }
    let metadata = table
        .schema_ref()
        .map(|schema| schema.metadata().clone())
        .unwrap_or_default();
    let fields: Vec<Field> = filtered
        .keys()
        .map(|field| field.as_ref().clone())
        .collect();
    let schema = Some(Schema::new_with_metadata(fields, metadata));
    TrackedTableOracle::new(schema, filtered, table.log_size())
}

fn count_output_payload_cols<B: SnarkBackend>(table: &TrackedTable<B>) -> usize {
    let cols = table.tracked_polys();
    let fields: Vec<FieldRef> = match table.schema_ref() {
        Some(schema) => schema
            .fields()
            .iter()
            .map(|field| Arc::new(field.as_ref().clone()))
            .collect(),
        None => cols.keys().cloned().collect(),
    };
    fields
        .into_iter()
        .filter(|field| {
            field.name() != arithmetic::ROW_ID_COL_NAME
                && field.name() != arithmetic::ACTIVATOR_COL_NAME
        })
        .count()
}

fn count_output_payload_cols_oracle<B: SnarkBackend>(table: &TrackedTableOracle<B>) -> usize {
    let cols = table.tracked_oracles();
    let fields: Vec<FieldRef> = match table.schema_ref() {
        Some(schema) => schema
            .fields()
            .iter()
            .map(|field| Arc::new(field.as_ref().clone()))
            .collect(),
        None => cols.keys().cloned().collect(),
    };
    fields
        .into_iter()
        .filter(|field| {
            field.name() != arithmetic::ROW_ID_COL_NAME
                && field.name() != arithmetic::ACTIVATOR_COL_NAME
        })
        .count()
}

fn output_lookup_base_from_output<B: SnarkBackend>(
    output: &TrackedTable<B>,
    left_table: &TrackedTable<B>,
    right_table: &TrackedTable<B>,
    use_left: bool,
) -> TrackedTable<B> {
    let left_width = count_output_payload_cols(left_table);
    let right_width = count_output_payload_cols(right_table);
    let start = if use_left { 0 } else { left_width };
    let len = if use_left { left_width } else { right_width };
    let output_cols = output.tracked_polys();
    let ordered_fields: Vec<FieldRef> = match output.schema_ref() {
        Some(schema) => schema
            .fields()
            .iter()
            .map(|field| Arc::new(field.as_ref().clone()))
            .collect(),
        None => output_cols.keys().cloned().collect(),
    };
    let mut data_fields = IndexMap::new();
    for field in ordered_fields
        .into_iter()
        .filter(|field| {
            field.name() != arithmetic::ACTIVATOR_COL_NAME
                && field.name() != arithmetic::ROW_ID_COL_NAME
        })
        .skip(start)
        .take(len)
    {
        let poly = output_cols
            .get(&field)
            .unwrap_or_else(|| panic!("Join output missing column {}", field.name()));
        data_fields.insert(field, poly.clone());
    }
    if data_fields.len() != len {
        panic!(
            "Join output missing {} {}-side payload columns",
            len,
            if use_left { "left" } else { "right" }
        );
    }
    let activator = output
        .activator_tracked_poly()
        .expect("Join output should carry an activator column");
    data_fields.insert(arithmetic::ACTIVATOR_FIELD.clone(), activator);
    let schema = Some(Schema::new(
        data_fields
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>(),
    ));
    TrackedTable::new(schema, data_fields, output.log_size())
}

fn output_lookup_base_from_output_oracle<B: SnarkBackend>(
    output: &TrackedTableOracle<B>,
    left_table: &TrackedTableOracle<B>,
    right_table: &TrackedTableOracle<B>,
    use_left: bool,
) -> TrackedTableOracle<B> {
    let left_width = count_output_payload_cols_oracle(left_table);
    let right_width = count_output_payload_cols_oracle(right_table);
    let start = if use_left { 0 } else { left_width };
    let len = if use_left { left_width } else { right_width };
    let output_cols = output.tracked_oracles();
    let ordered_fields: Vec<FieldRef> = match output.schema_ref() {
        Some(schema) => schema
            .fields()
            .iter()
            .map(|field| Arc::new(field.as_ref().clone()))
            .collect(),
        None => output_cols.keys().cloned().collect(),
    };
    let mut data_fields = IndexMap::new();
    for field in ordered_fields
        .into_iter()
        .filter(|field| {
            field.name() != arithmetic::ACTIVATOR_COL_NAME
                && field.name() != arithmetic::ROW_ID_COL_NAME
        })
        .skip(start)
        .take(len)
    {
        let oracle = output_cols
            .get(&field)
            .unwrap_or_else(|| panic!("Join output missing column {}", field.name()));
        data_fields.insert(field, oracle.clone());
    }
    if data_fields.len() != len {
        panic!(
            "Join output missing {} {}-side payload columns",
            len,
            if use_left { "left" } else { "right" }
        );
    }
    let activator = output
        .activator_tracked_poly()
        .expect("Join output should carry an activator column");
    data_fields.insert(arithmetic::ACTIVATOR_FIELD.clone(), activator);
    let schema = Some(Schema::new(
        data_fields
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>(),
    ));
    TrackedTableOracle::new(schema, data_fields, output.log_size())
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
            let output_left_base = payload.get(OUTPUT_LEFT_LABEL).cloned().unwrap_or_else(|| {
                output_lookup_base_from_output(&output, &left_table, &right_table, true)
            });
            let output_right_base = payload.get(OUTPUT_RIGHT_LABEL).cloned().unwrap_or_else(|| {
                output_lookup_base_from_output(&output, &left_table, &right_table, false)
            });
            // Purpose: Every row in the output table must consist of columns that come from some row in the left table.
            // Method: We look up table output_left in input_left
            // output left = [output activator | output keys + Output data coming from the left table + their source row number from the left table]
            // input left = [left activator | left keys + left data + normal index]
            let output_left = output_left_base;

            let index_poly = index_tracked_poly(prover, &left_table);
            let input_left_base = input_lookup_base_from_table(&left_table);
            let input_left = append_tracked_col(
                &input_left_base,
                Arc::new(Field::new(SRC_LEFT_COL_NAME, DataType::Int64, true)),
                index_poly,
            );
            // Fold both sides with the same transcript challenges for this lookup.
            let left_fold_challs =
                lookup_fold_challenges_prover(prover, output_left.num_data_tracked_cols())?;
            let output_folded = fold_lookup_table_prover(&output_left, &left_fold_challs);
            let input_folded = fold_lookup_table_prover(&input_left, &left_fold_challs);

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

            let output_right = output_right_base;

            let right_index_poly = index_tracked_poly(prover, &right_table);
            let input_right_base = input_lookup_base_from_table(&right_table);
            let input_right = append_tracked_col(
                &input_right_base,
                Arc::new(Field::new(SRC_RIGHT_COL_NAME, DataType::Int64, true)),
                right_index_poly,
            );
            // Fold both sides with the same transcript challenges for this lookup.
            let right_fold_challs =
                lookup_fold_challenges_prover(prover, output_right.num_data_tracked_cols())?;
            let output_right_folded = fold_lookup_table_prover(&output_right, &right_fold_challs);
            let input_right_folded = fold_lookup_table_prover(&input_right, &right_fold_challs);
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
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        use ark_piop::errors::SnarkError;
        use ark_piop::prover::errors::{HonestProverError, ProverError};
        use indexmap::IndexSet;

        if self.many_to_many_gadgets().is_none() {
            return Ok(());
        }

        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };

        let Some(output) = payload.get(OUTPUT_LABEL).cloned() else {
            return Ok(());
        };
        let Some(left_table) = payload.get(LEFT_LABEL).cloned() else {
            return Ok(());
        };
        let Some(right_table) = payload.get(RIGHT_LABEL).cloned() else {
            return Ok(());
        };

        let output_left = payload.get(OUTPUT_LEFT_LABEL).cloned().unwrap_or_else(|| {
            output_lookup_base_from_output(&output, &left_table, &right_table, true)
        });
        let output_right = payload.get(OUTPUT_RIGHT_LABEL).cloned().unwrap_or_else(|| {
            output_lookup_base_from_output(&output, &left_table, &right_table, false)
        });

        let index_poly = index_tracked_poly(prover, &left_table);
        let input_left = append_tracked_col(
            &input_lookup_base_from_table(&left_table),
            Arc::new(Field::new(SRC_LEFT_COL_NAME, DataType::Int64, true)),
            index_poly,
        );
        let left_fold_challs =
            lookup_fold_challenges_prover(prover, output_left.num_data_tracked_cols())?;
        let output_left_folded = fold_lookup_table_prover(&output_left, &left_fold_challs);
        let input_left_folded = fold_lookup_table_prover(&input_left, &left_fold_challs);
        let left_super_set: IndexSet<B::F> = input_left_folded.effective_hashset();
        for value in output_left_folded.effective_iter() {
            if !left_super_set.contains(&value) {
                tracing::debug!(
                    node_id = ?id,
                    side = "left",
                    "join honest check found output-left row missing from left input lookup table"
                );
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }

        let right_index_poly = index_tracked_poly(prover, &right_table);
        let input_right = append_tracked_col(
            &input_lookup_base_from_table(&right_table),
            Arc::new(Field::new(SRC_RIGHT_COL_NAME, DataType::Int64, true)),
            right_index_poly,
        );
        let right_fold_challs =
            lookup_fold_challenges_prover(prover, output_right.num_data_tracked_cols())?;
        let output_right_folded = fold_lookup_table_prover(&output_right, &right_fold_challs);
        let input_right_folded = fold_lookup_table_prover(&input_right, &right_fold_challs);
        let right_super_set: IndexSet<B::F> = input_right_folded.effective_hashset();
        for value in output_right_folded.effective_iter() {
            if !right_super_set.contains(&value) {
                tracing::debug!(
                    node_id = ?id,
                    side = "right",
                    "join honest check found output-right row missing from right input lookup table"
                );
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }

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
            let output_left_base = payload.get(OUTPUT_LEFT_LABEL).cloned().unwrap_or_else(|| {
                output_lookup_base_from_output_oracle(&output, &left_table, &right_table, true)
            });
            let output_right_base = payload.get(OUTPUT_RIGHT_LABEL).cloned().unwrap_or_else(|| {
                output_lookup_base_from_output_oracle(&output, &left_table, &right_table, false)
            });
            let output_left = output_left_base;

            let index_oracle = index_tracked_oracle(verifier, &left_table);
            let input_left_base = input_lookup_base_from_table_oracle(&left_table);
            let input_left = append_tracked_oracle(
                &input_left_base,
                Arc::new(Field::new(SRC_LEFT_COL_NAME, DataType::Int64, true)),
                index_oracle,
            );

            // Mirror prover-side challenge reuse exactly.
            let left_fold_challs = lookup_fold_challenges_verifier(
                verifier,
                output_left.num_data_tracked_col_oracles(),
            )?;
            let output_folded = fold_lookup_table_verifier(&output_left, &left_fold_challs);
            let input_folded = fold_lookup_table_verifier(&input_left, &left_fold_challs);

            LookupPIOP::<B>::verify(
                verifier,
                LookupVerifierInput {
                    included_tracked_col_oracles: vec![output_folded],
                    super_tracked_col_oracle: input_folded,
                },
            )?;

            let output_right = output_right_base;

            let right_index_oracle = index_tracked_oracle(verifier, &right_table);
            let input_right_base = input_lookup_base_from_table_oracle(&right_table);
            let input_right = append_tracked_oracle(
                &input_right_base,
                Arc::new(Field::new(SRC_RIGHT_COL_NAME, DataType::Int64, true)),
                right_index_oracle,
            );

            // Mirror prover-side challenge reuse exactly.
            let right_fold_challs = lookup_fold_challenges_verifier(
                verifier,
                output_right.num_data_tracked_col_oracles(),
            )?;
            let output_right_folded = fold_lookup_table_verifier(&output_right, &right_fold_challs);
            let input_right_folded = fold_lookup_table_verifier(&input_right, &right_fold_challs);

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

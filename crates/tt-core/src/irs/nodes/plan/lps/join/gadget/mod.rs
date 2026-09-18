use std::sync::Arc;

use crate::irs::{
    nodes::{
        IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps,
        utils::{
            prescr_perm, validate_tracked_oracle_table_row_domain,
            validate_tracked_table_row_domain,
        },
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
use datafusion_expr::{Expr, Join, JoinType};
use either::Either;
use indexmap::IndexMap;
use std::cell::RefCell;
use std::sync::RwLock;

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

fn unsupported_join_error(message: impl Into<String>) -> ark_piop::errors::SnarkError {
    ark_piop::errors::SnarkError::VerifierError(
        ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(format!(
            "Join proof supports only plain inner equijoins: {}",
            message.into()
        )),
    )
}

fn join_wiring_error(message: impl Into<String>) -> ark_piop::errors::SnarkError {
    ark_piop::errors::SnarkError::VerifierError(
        ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(format!(
            "Join proof wiring: {}",
            message.into()
        )),
    )
}

/// Fail closed on logical join shapes that the current Join proof does not
/// model. In the full MANY_TO_MANY path, MatchPair proves a nonempty
/// conjunction of column equalities and its count formula is exactly the
/// cardinality of an inner equijoin. Outer joins, cross joins, and residual
/// filters require different relations in every optimization mode. Nullable
/// payloads are also excluded because the current arithmetic encoding maps
/// NULL to zero without committing a row-level validity bit. A provenance
/// lookup therefore cannot distinguish a true NULL from the ordinary value
/// zero, even when the nullable column is not itself a join key.
fn ensure_supported_join(join: &Join) -> ark_piop::errors::SnarkResult<()> {
    if join.join_type != JoinType::Inner {
        return Err(unsupported_join_error("join type must be INNER"));
    }
    if join.on.is_empty() {
        return Err(unsupported_join_error(
            "at least one equijoin key pair is required",
        ));
    }
    if join.filter.is_some() {
        return Err(unsupported_join_error(
            "residual join filters are not yet constrained",
        ));
    }

    for (side, schema) in [("left", join.left.schema()), ("right", join.right.schema())] {
        for (_, field) in schema.iter() {
            if !arithmetic::is_system_column(field.name()) && field.is_nullable() {
                return Err(unsupported_join_error(format!(
                    "{side} payload column {} is nullable, but NULL validity is not encoded",
                    field.name()
                )));
            }
        }
    }

    for (key_index, (left, right)) in join.on.iter().enumerate() {
        let (Expr::Column(left), Expr::Column(right)) = (left, right) else {
            return Err(unsupported_join_error(format!(
                "key pair {key_index} must consist of direct column references"
            )));
        };
        let left_field = join.left.schema().field_from_column(left).map_err(|err| {
            unsupported_join_error(format!(
                "cannot resolve left key {} at position {key_index}: {err}",
                left.flat_name()
            ))
        })?;
        let right_field = join
            .right
            .schema()
            .field_from_column(right)
            .map_err(|err| {
                unsupported_join_error(format!(
                    "cannot resolve right key {} at position {key_index}: {err}",
                    right.flat_name()
                ))
            })?;
        if left_field.is_nullable() || right_field.is_nullable() {
            return Err(unsupported_join_error(format!(
                "key pair {key_index} is nullable (left={}, right={}), but NULL validity is not encoded",
                left_field.is_nullable(),
                right_field.is_nullable(),
            )));
        }
        if left_field.data_type() != right_field.data_type() {
            return Err(unsupported_join_error(format!(
                "key pair {key_index} has different left/right encoding types"
            )));
        }
    }
    Ok(())
}

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
        // These are helper projections of __OUTPUT__ used by the join lookup PIOP.
        // Keep them virtual so only the full join output is committed.
        output_left_hint: crate::irs::nodes::hints::HintDF::new_virtual(output_left_df),
        output_right_hint: crate::irs::nodes::hints::HintDF::new_virtual(output_right_df),
        src_left_hint: build_prover_source_hint(left_src_df, SRC_LEFT_COL_NAME),
        src_right_hint: build_prover_source_hint(right_src_df, SRC_RIGHT_COL_NAME),
        nodup_input_hint: build_nodup_input_hint(nodup_input_df),
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

fn find_parent_id<B: SnarkBackend>(
    id: crate::irs::nodes::NodeId,
    tree: &crate::irs::tree::Tree<B>,
) -> Option<crate::irs::nodes::NodeId> {
    tree.arena().iter().find_map(|(node_id, node)| {
        let is_parent = node.children().iter().any(|child| child.id() == id);
        is_parent.then_some(*node_id)
    })
}

fn parent_child_id<B: SnarkBackend>(
    id: crate::irs::nodes::NodeId,
    tree: &crate::irs::tree::Tree<B>,
    child_idx: usize,
) -> Option<crate::irs::nodes::NodeId> {
    let parent_id = find_parent_id(id, tree)?;
    let parent = tree.arena().get(&parent_id)?;
    parent.children().get(child_idx).map(|child| child.id())
}

fn parent_plan_output_table<B: SnarkBackend>(
    id: crate::irs::nodes::NodeId,
    ir: &crate::prover::irs::VirtualizedIr<B>,
) -> Option<&TrackedTable<B>> {
    let parent_id = find_parent_id(id, ir.tree())?;
    match ir.payload_for_node(&parent_id) {
        Some(PayloadStructure::PlanPayload(table)) => Some(table),
        _ => None,
    }
}

fn parent_plan_side_table<B: SnarkBackend>(
    id: crate::irs::nodes::NodeId,
    ir: &crate::prover::irs::VirtualizedIr<B>,
    child_idx: usize,
) -> Option<&TrackedTable<B>> {
    let child_id = parent_child_id(id, ir.tree(), child_idx)?;
    match ir.payload_for_node(&child_id) {
        Some(PayloadStructure::PlanPayload(table)) => Some(table),
        _ => None,
    }
}

fn parent_plan_output_table_gadget_ready<B: SnarkBackend>(
    id: crate::irs::nodes::NodeId,
    ir: &GadgetReadyIr<B>,
) -> Option<&TrackedTable<B>> {
    let parent_id = find_parent_id(id, ir.tree())?;
    match ir.payload_for_node(&parent_id) {
        Some(PayloadStructure::PlanPayload(table)) => Some(table),
        _ => None,
    }
}

fn parent_plan_side_table_gadget_ready<B: SnarkBackend>(
    id: crate::irs::nodes::NodeId,
    ir: &GadgetReadyIr<B>,
    child_idx: usize,
) -> Option<&TrackedTable<B>> {
    let child_id = parent_child_id(id, ir.tree(), child_idx)?;
    match ir.payload_for_node(&child_id) {
        Some(PayloadStructure::PlanPayload(table)) => Some(table),
        _ => None,
    }
}

fn parent_plan_output_oracle<B: SnarkBackend>(
    id: crate::irs::nodes::NodeId,
    ir: &crate::verifier::irs::VirtualizedIr<B>,
) -> Option<&TrackedTableOracle<B>> {
    let parent_id = find_parent_id(id, ir.tree())?;
    match ir.payload_for_node(&parent_id) {
        Some(PayloadStructure::PlanPayload(table)) => Some(table),
        _ => None,
    }
}

fn parent_plan_side_oracle<B: SnarkBackend>(
    id: crate::irs::nodes::NodeId,
    ir: &crate::verifier::irs::VirtualizedIr<B>,
    child_idx: usize,
) -> Option<&TrackedTableOracle<B>> {
    let child_id = parent_child_id(id, ir.tree(), child_idx)?;
    match ir.payload_for_node(&child_id) {
        Some(PayloadStructure::PlanPayload(table)) => Some(table),
        _ => None,
    }
}

fn parent_plan_output_oracle_gadget_ready<B: SnarkBackend>(
    id: crate::irs::nodes::NodeId,
    ir: &crate::verifier::irs::GadgetReadyIr<B>,
) -> Option<&TrackedTableOracle<B>> {
    let parent_id = find_parent_id(id, ir.tree())?;
    match ir.payload_for_node(&parent_id) {
        Some(PayloadStructure::PlanPayload(table)) => Some(table),
        _ => None,
    }
}

fn parent_plan_side_oracle_gadget_ready<B: SnarkBackend>(
    id: crate::irs::nodes::NodeId,
    ir: &crate::verifier::irs::GadgetReadyIr<B>,
    child_idx: usize,
) -> Option<&TrackedTableOracle<B>> {
    let child_id = parent_child_id(id, ir.tree(), child_idx)?;
    match ir.payload_for_node(&child_id) {
        Some(PayloadStructure::PlanPayload(table)) => Some(table),
        _ => None,
    }
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
    // Reserved representation for a future PK/FK-specific proof. It must not
    // be selected until it constrains the materialized output relation.
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
        ensure_supported_join(&self.join)?;
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
                output_hint: _output_hint,
                output_left_hint: _output_left_hint,
                output_right_hint: _output_right_hint,
                src_left_hint,
                src_right_hint,
                nodup_input_hint,
            } = derived;
            // Overwrite with the concretized hints so later join-subgadgets (and
            // provenance checks) see the same materialized inputs used to derive
            // source-row hints.
            gadget_payload.swap_remove(LEFT_LABEL);
            gadget_payload.swap_remove(RIGHT_LABEL);
            gadget_payload.swap_remove(OUTPUT_LABEL);
            gadget_payload.insert(SRC_LEFT_LABEL.to_string(), src_left_hint);
            gadget_payload.insert(SRC_RIGHT_LABEL.to_string(), src_right_hint);
            planned_ir
                .set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));

            let mut nodup_payload = match planned_ir.payload_for_node(&gadgets.nodup_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            nodup_payload.insert(
                crate::irs::nodes::utils::nodup::INPUT_LABEL.to_string(),
                nodup_input_hint,
            );
            planned_ir.set_payload_for_node(
                gadgets.nodup_gadget.id(),
                Some(PayloadStructure::GadgetPayload(nodup_payload)),
            );

            let match_pair_payload =
                match planned_ir.payload_for_node(&gadgets.match_pair_gadget.id()) {
                    Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                    _ => IndexMap::new(),
                };
            crate::irs::nodes::utils::match_pair_check::cache_match_pair_planning_context(
                gadgets.match_pair_gadget.id(),
                left_hint.clone(),
                right_hint.clone(),
                self.join.clone(),
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
        ensure_supported_join(&self.join)?;
        if self.many_to_many_gadgets().is_some() {
            // First fetch the payload for the current node, prepared by the parent
            let Some(PayloadStructure::GadgetPayload(payload)) =
                virtualized_ir.payload_for_node(&id).cloned()
            else {
                panic!("Expected gadget payload for Join gadget node")
            };
            // Among the payload, we expect left, right, and output tables
            let current_output = parent_plan_output_table(id, virtualized_ir)
                .cloned()
                .unwrap_or_else(|| panic!("Join parent plan payload missing output table"));
            let current_left = parent_plan_side_table(id, virtualized_ir, 0)
                .cloned()
                .unwrap_or_else(|| panic!("Join parent plan payload missing left input table"));
            let current_right = parent_plan_side_table(id, virtualized_ir, 1)
                .cloned()
                .unwrap_or_else(|| panic!("Join parent plan payload missing right input table"));
            let current_left_src = payload
                .get(SRC_LEFT_LABEL)
                .unwrap_or_else(|| panic!("Join gadget payload missing {SRC_LEFT_LABEL}"));
            let current_right_src = payload
                .get(SRC_RIGHT_LABEL)
                .unwrap_or_else(|| panic!("Join gadget payload missing {SRC_RIGHT_LABEL}"));
            validate_tracked_table_row_domain(&current_output, "join output")?;
            validate_tracked_table_row_domain(&current_left, "join left input")?;
            validate_tracked_table_row_domain(&current_right, "join right input")?;
            validate_tracked_table_row_domain(current_left_src, "join src-left")?;
            validate_tracked_table_row_domain(current_right_src, "join src-right")?;
            current_output
                .activator_tracked_poly()
                .ok_or_else(|| join_wiring_error("join output is missing its activator"))?;
            self.wire_prover_bool_payload(&current_output, virtualized_ir);

            self.wire_prover_nodup_payload(
                &current_output,
                current_left_src,
                current_right_src,
                virtualized_ir,
            )?;

            self.wire_prover_match_pair_payload(
                &current_output,
                &current_left,
                &current_right,
                virtualized_ir,
            )?;
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
        ensure_supported_join(&self.join)?;
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
                output_hint: _output_hint,
                output_left_hint: _output_left_hint,
                output_right_hint: _output_right_hint,
                src_left_hint,
                src_right_hint,
                nodup_input_hint,
            } = derived;
            gadget_payload.swap_remove(LEFT_LABEL);
            gadget_payload.swap_remove(RIGHT_LABEL);
            gadget_payload.swap_remove(OUTPUT_LABEL);
            gadget_payload.insert(SRC_LEFT_LABEL.to_string(), src_left_hint);
            gadget_payload.insert(SRC_RIGHT_LABEL.to_string(), src_right_hint);
            planned_ir
                .set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));

            let mut nodup_payload = match planned_ir.payload_for_node(&gadgets.nodup_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            nodup_payload.insert(
                crate::irs::nodes::utils::nodup::INPUT_LABEL.to_string(),
                nodup_input_hint,
            );
            planned_ir.set_payload_for_node(
                gadgets.nodup_gadget.id(),
                Some(PayloadStructure::GadgetPayload(nodup_payload)),
            );

            let match_pair_payload =
                match planned_ir.payload_for_node(&gadgets.match_pair_gadget.id()) {
                    Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                    _ => IndexMap::new(),
                };
            crate::irs::nodes::utils::match_pair_check::cache_match_pair_planning_context(
                gadgets.match_pair_gadget.id(),
                left_hint.clone(),
                right_hint.clone(),
                self.join.clone(),
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
        ensure_supported_join(&self.join)?;
        if self.many_to_many_gadgets().is_some() {
            let (current_output, current_left, current_right, current_left_src, current_right_src) = {
                let Some(PayloadStructure::GadgetPayload(payload)) =
                    virtualized_ir.payload_for_node(&id)
                else {
                    panic!("expected gadget payload for Join gadget node")
                };
                (
                    parent_plan_output_oracle(id, virtualized_ir)
                        .unwrap_or_else(|| panic!("Join parent plan payload missing output oracle"))
                        .clone(),
                    parent_plan_side_oracle(id, virtualized_ir, 0)
                        .unwrap_or_else(|| {
                            panic!("Join parent plan payload missing left input oracle")
                        })
                        .clone(),
                    parent_plan_side_oracle(id, virtualized_ir, 1)
                        .unwrap_or_else(|| {
                            panic!("Join parent plan payload missing right input oracle")
                        })
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
            validate_tracked_oracle_table_row_domain(&current_output, "join output")?;
            validate_tracked_oracle_table_row_domain(&current_left, "join left input")?;
            validate_tracked_oracle_table_row_domain(&current_right, "join right input")?;
            validate_tracked_oracle_table_row_domain(&current_left_src, "join src-left")?;
            validate_tracked_oracle_table_row_domain(&current_right_src, "join src-right")?;
            current_output
                .activator_tracked_poly()
                .ok_or_else(|| join_wiring_error("join output is missing its activator"))?;
            self.wire_verifier_bool_payload(&current_output, virtualized_ir);

            self.wire_verifier_nodup_payload(
                &current_output,
                &current_left_src,
                &current_right_src,
                virtualized_ir,
            )?;

            self.wire_verifier_match_pair_payload(
                &current_output,
                &current_left,
                &current_right,
                virtualized_ir,
            )?;
            Ok(())
        } else {
            Ok(())
        }
    }
}

fn derive_many_to_many_hints_verifier(
    _join: &Join,
    left_hint: &crate::irs::nodes::hints::HintDF,
    right_hint: &crate::irs::nodes::hints::HintDF,
    output_hint: &crate::irs::nodes::hints::HintDF,
) -> JoinPlanningDerivedHints {
    let left_hint = force_materialize_all(&force_materialize_row_id(left_hint));
    let right_hint = force_materialize_all(&force_materialize_row_id(right_hint));
    let output_hint = force_materialize_all(&force_materialize_row_id(output_hint));

    JoinPlanningDerivedHints {
        output_left_hint: build_verifier_output_side_hint(&left_hint, SRC_LEFT_COL_NAME),
        output_right_hint: build_verifier_output_side_hint(&right_hint, SRC_RIGHT_COL_NAME),
        left_hint,
        right_hint,
        output_hint,
        src_left_hint: build_verifier_source_hint(SRC_LEFT_COL_NAME),
        src_right_hint: build_verifier_source_hint(SRC_RIGHT_COL_NAME),
        nodup_input_hint: build_verifier_nodup_input_hint(),
    }
}

fn build_verifier_output_side_hint(
    base_hint: &crate::irs::nodes::hints::HintDF,
    src_col_name: &str,
) -> crate::irs::nodes::hints::HintDF {
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
    crate::irs::nodes::hints::HintDF::new_virtual(df)
}

fn build_verifier_source_hint(src_col_name: &str) -> crate::irs::nodes::hints::HintDF {
    build_prover_source_hint(
        crate::irs::nodes::hints::schema_only_df(vec![
            Field::new(src_col_name, DataType::Int64, false),
            arithmetic::ACTIVATOR_FIELD.as_ref().clone(),
            arithmetic::ROW_ID_FIELD.as_ref().clone(),
        ]),
        src_col_name,
    )
}

fn build_prover_source_hint(
    df: datafusion::prelude::DataFrame,
    src_col_name: &str,
) -> crate::irs::nodes::hints::HintDF {
    let should_materialize = df
        .schema()
        .fields()
        .iter()
        .map(|field| (field.clone(), field.name() == src_col_name))
        .collect();
    crate::irs::nodes::hints::HintDF::new(df, should_materialize)
}

fn build_nodup_input_hint(df: datafusion::prelude::DataFrame) -> crate::irs::nodes::hints::HintDF {
    let should_materialize = df
        .schema()
        .fields()
        .iter()
        .map(|field| (field.clone(), field.name() != arithmetic::ROW_ID_COL_NAME))
        .collect();
    crate::irs::nodes::hints::HintDF::new(df, should_materialize)
}

fn build_verifier_nodup_input_hint() -> crate::irs::nodes::hints::HintDF {
    build_nodup_input_hint(crate::irs::nodes::hints::schema_only_df(vec![
        Field::new(SRC_LEFT_COL_NAME, DataType::Int64, false),
        Field::new(SRC_RIGHT_COL_NAME, DataType::Int64, false),
        arithmetic::ACTIVATOR_FIELD.as_ref().clone(),
        arithmetic::ROW_ID_FIELD.as_ref().clone(),
    ]))
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
) -> ark_piop::errors::SnarkResult<TrackedCol<B>> {
    let data_indices = table.data_tracked_polys_indices();
    if data_indices.is_empty() || data_indices.len() != challenges.len() {
        return Err(join_wiring_error(format!(
            "lookup table has {} data fields but {} fold challenges",
            data_indices.len(),
            challenges.len()
        )));
    }
    if data_indices.len() == 1 {
        return Ok(table.tracked_col_by_ind(data_indices[0]));
    }
    Ok(table.fold_all_data_columns(challenges))
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
) -> ark_piop::errors::SnarkResult<TrackedColOracle<B>> {
    let data_indices = table.data_tracked_oracles_indices();
    if data_indices.is_empty() || data_indices.len() != challenges.len() {
        return Err(join_wiring_error(format!(
            "lookup oracle table has {} data fields but {} fold challenges",
            data_indices.len(),
            challenges.len()
        )));
    }
    if data_indices.len() == 1 {
        return Ok(table.tracked_col_oracle_by_ind(data_indices[0]));
    }
    Ok(table.fold_all_data_oracles(challenges))
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
) -> ark_piop::errors::SnarkResult<TrackedTable<B>> {
    validate_tracked_table_row_domain(table, "join lookup table")?;
    let existing = table
        .tracked_polys()
        .first()
        .map(|(_, existing)| existing.clone())
        .ok_or_else(|| join_wiring_error("join lookup table has no row-domain columns"))?;
    if !existing.same_tracker(&poly) {
        return Err(join_wiring_error(
            "source index and join lookup table belong to different proof trackers",
        ));
    }
    if poly.log_size() != table.log_size() {
        return Err(join_wiring_error(format!(
            "source index has log size {}, expected {}",
            poly.log_size(),
            table.log_size()
        )));
    }
    let mut tracked_polys = table.tracked_polys();
    if tracked_polys
        .keys()
        .any(|existing| existing.name() == field.name())
    {
        return Err(join_wiring_error(format!(
            "reserved source-index column {} collides with a payload field",
            field.name()
        )));
    }
    let old_width = table.num_data_tracked_cols();
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
    let result = TrackedTable::new(schema, tracked_polys, table.log_size());
    if result.num_data_tracked_cols() != old_width + 1 {
        return Err(join_wiring_error(
            "appending a source index did not increase lookup width by one",
        ));
    }
    Ok(result)
}

fn single_data_poly_from_table<B: SnarkBackend>(
    table: &TrackedTable<B>,
    label: &str,
) -> ark_piop::errors::SnarkResult<TrackedPoly<B>> {
    validate_tracked_table_row_domain(table, &format!("Join {label} table"))?;
    let data_indices = table.data_tracked_polys_indices();
    if data_indices.len() != 1 {
        return Err(join_wiring_error(format!(
            "Join {label} table must have exactly one data column"
        )));
    }
    Ok(table
        .tracked_col_by_ind(data_indices[0])
        .data_tracked_poly())
}

fn append_tracked_oracle<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    field: FieldRef,
    oracle: TrackedOracle<B>,
) -> ark_piop::errors::SnarkResult<TrackedTableOracle<B>> {
    validate_tracked_oracle_table_row_domain(table, "join lookup oracle table")?;
    let existing = table
        .tracked_oracles()
        .first()
        .map(|(_, existing)| existing.clone())
        .ok_or_else(|| join_wiring_error("join lookup oracle table has no row-domain columns"))?;
    if !existing.same_tracker(&oracle) {
        return Err(join_wiring_error(
            "source-index oracle and join lookup table belong to different proof trackers",
        ));
    }
    if oracle.log_size() != table.log_size() {
        return Err(join_wiring_error(format!(
            "source-index oracle has log size {}, expected {}",
            oracle.log_size(),
            table.log_size()
        )));
    }
    let mut tracked_oracles = table.tracked_oracles();
    if tracked_oracles
        .keys()
        .any(|existing| existing.name() == field.name())
    {
        return Err(join_wiring_error(format!(
            "reserved source-index column {} collides with a payload field",
            field.name()
        )));
    }
    let old_width = table.num_data_tracked_col_oracles();
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
    let result = TrackedTableOracle::new(schema, tracked_oracles, table.log_size());
    if result.num_data_tracked_col_oracles() != old_width + 1 {
        return Err(join_wiring_error(
            "appending a source-index oracle did not increase lookup width by one",
        ));
    }
    Ok(result)
}

fn single_data_oracle_from_table<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    label: &str,
) -> ark_piop::errors::SnarkResult<TrackedOracle<B>> {
    validate_tracked_oracle_table_row_domain(table, &format!("Join {label} table"))?;
    let data_indices = table.data_tracked_oracles_indices();
    if data_indices.len() != 1 {
        return Err(join_wiring_error(format!(
            "Join {label} table must have exactly one data column"
        )));
    }
    Ok(table
        .tracked_col_oracle_by_ind(data_indices[0])
        .data_tracked_oracle())
}

fn input_lookup_base_from_table<B: SnarkBackend>(
    table: &TrackedTable<B>,
) -> ark_piop::errors::SnarkResult<TrackedTable<B>> {
    validate_tracked_table_row_domain(table, "join input")?;
    let cols = table.tracked_polys();
    let actual_fields = cols.keys().cloned().collect::<Vec<_>>();
    validate_flat_field_order(
        table.schema_ref(),
        &actual_fields,
        table.num_total_tracked_cols(),
        "join input",
    )?;
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
        let poly = cols.get(&field).ok_or_else(|| {
            join_wiring_error(format!(
                "join input table is missing column {}",
                field.name()
            ))
        })?;
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
    Ok(TrackedTable::new(schema, filtered, table.log_size()))
}

fn input_lookup_base_from_table_oracle<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
) -> ark_piop::errors::SnarkResult<TrackedTableOracle<B>> {
    validate_tracked_oracle_table_row_domain(table, "join input")?;
    let cols = table.tracked_oracles();
    let actual_fields = cols.keys().cloned().collect::<Vec<_>>();
    validate_flat_field_order(
        table.schema_ref(),
        &actual_fields,
        table.num_total_tracked_col_oracles(),
        "join input oracle",
    )?;
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
        let oracle = cols.get(&field).ok_or_else(|| {
            join_wiring_error(format!(
                "join input oracle is missing column {}",
                field.name()
            ))
        })?;
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
    Ok(TrackedTableOracle::new(schema, filtered, table.log_size()))
}

fn validate_flat_field_order(
    schema: Option<&Schema>,
    actual_fields: &[FieldRef],
    declared_flat_width: usize,
    label: &str,
) -> ark_piop::errors::SnarkResult<()> {
    // `TrackedTable::{new,new_with_side_cols}` historically checked this only
    // under debug assertions and compared schema/map order with `zip`. In a
    // release build, a duplicate `FieldRef` can collapse in the `IndexMap`, or
    // a short map can silently truncate that comparison. Both cases are fatal
    // for positional join provenance, so enforce the full shape here.
    if actual_fields.len() != declared_flat_width {
        return Err(join_wiring_error(format!(
            "{label} contains {declared_flat_width} row-domain segments but only {} distinct committed fields",
            actual_fields.len()
        )));
    }
    if let Some(schema) = schema {
        if schema.fields().len() != actual_fields.len() {
            return Err(join_wiring_error(format!(
                "{label} schema has {} fields but its committed table has {}",
                schema.fields().len(),
                actual_fields.len()
            )));
        }
        for (index, (declared, actual)) in schema.fields().iter().zip(actual_fields).enumerate() {
            if declared.as_ref() != actual.as_ref() {
                return Err(join_wiring_error(format!(
                    "{label} schema field {index} does not match the committed field order"
                )));
            }
        }
    }
    Ok(())
}

fn validated_data_polys<B: SnarkBackend>(
    table: &TrackedTable<B>,
    label: &str,
) -> ark_piop::errors::SnarkResult<Vec<(FieldRef, TrackedPoly<B>)>> {
    validate_tracked_table_row_domain(table, label)?;
    let flat = table.tracked_polys();
    let fields = flat.keys().cloned().collect::<Vec<_>>();
    validate_flat_field_order(
        table.schema_ref(),
        &fields,
        table.num_total_tracked_cols(),
        label,
    )?;
    Ok(flat
        .into_iter()
        .filter(|(field, _)| !arithmetic::is_system_column(field.name()))
        .collect())
}

fn validated_data_oracles<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    label: &str,
) -> ark_piop::errors::SnarkResult<Vec<(FieldRef, TrackedOracle<B>)>> {
    validate_tracked_oracle_table_row_domain(table, label)?;
    let flat = table.tracked_oracles();
    let fields = flat.keys().cloned().collect::<Vec<_>>();
    validate_flat_field_order(
        table.schema_ref(),
        &fields,
        table.num_total_tracked_col_oracles(),
        label,
    )?;
    Ok(flat
        .into_iter()
        .filter(|(field, _)| !arithmetic::is_system_column(field.name()))
        .collect())
}

fn field_provenance(field: &FieldRef) -> (Option<&str>, &str) {
    (
        field.metadata().get("tt.qualifier").map(String::as_str),
        field.name(),
    )
}

fn field_metadata_without_constraints(
    field: &FieldRef,
) -> std::collections::HashMap<String, String> {
    let mut metadata = field.metadata().clone();
    metadata.remove("tt.pk");
    metadata.remove("tt.fk.ref_table");
    metadata.remove("tt.fk.ref_columns");
    metadata
}

fn fields_are_positionally_compatible(actual: &FieldRef, expected: &FieldRef) -> bool {
    // MANY_TO_MANY deliberately strips PK/FK constraint metadata from join
    // output fields. Those annotations are not part of row provenance; the
    // remaining metadata, exact qualifier/name, Arrow type, and nullability
    // are. Comparing all other metadata keeps extension/encoding annotations
    // from being silently discarded.
    field_provenance(actual) == field_provenance(expected)
        && actual.data_type() == expected.data_type()
        && actual.is_nullable() == expected.is_nullable()
        && field_metadata_without_constraints(actual)
            == field_metadata_without_constraints(expected)
}

fn output_lookup_base_from_output<B: SnarkBackend>(
    output: &TrackedTable<B>,
    left_table: &TrackedTable<B>,
    right_table: &TrackedTable<B>,
    use_left: bool,
) -> ark_piop::errors::SnarkResult<TrackedTable<B>> {
    let left = validated_data_polys(left_table, "left input")?;
    let right = validated_data_polys(right_table, "right input")?;
    let output_data = validated_data_polys(output, "join output")?;
    let expected_fields = left
        .iter()
        .chain(&right)
        .map(|(field, _)| field)
        .collect::<Vec<_>>();
    if output_data.len() != expected_fields.len() {
        return Err(join_wiring_error(format!(
            "join output has {} data fields, expected {} left/right fields",
            output_data.len(),
            expected_fields.len()
        )));
    }
    for (index, ((output_field, _), expected_field)) in
        output_data.iter().zip(expected_fields).enumerate()
    {
        if !fields_are_positionally_compatible(output_field, expected_field) {
            return Err(join_wiring_error(format!(
                "join output field {index} does not match its positional input field"
            )));
        }
    }
    if left.iter().any(|(left_field, _)| {
        right
            .iter()
            .any(|(right_field, _)| field_provenance(left_field) == field_provenance(right_field))
    }) {
        return Err(join_wiring_error(
            "left/right payload fields are not provenance-disjoint; alias self-join inputs explicitly",
        ));
    }

    let left_width = left.len();
    let selected = if use_left {
        &output_data[..left_width]
    } else {
        &output_data[left_width..]
    };
    let mut data_fields = selected.iter().cloned().collect::<IndexMap<_, _>>();
    let activator = output
        .activator_tracked_poly()
        .ok_or_else(|| join_wiring_error("join output is missing its activator"))?;
    data_fields.insert(arithmetic::ACTIVATOR_FIELD.clone(), activator);
    let schema = Some(Schema::new(
        data_fields
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>(),
    ));
    Ok(TrackedTable::new(schema, data_fields, output.log_size()))
}

fn output_lookup_base_from_output_oracle<B: SnarkBackend>(
    output: &TrackedTableOracle<B>,
    left_table: &TrackedTableOracle<B>,
    right_table: &TrackedTableOracle<B>,
    use_left: bool,
) -> ark_piop::errors::SnarkResult<TrackedTableOracle<B>> {
    let left = validated_data_oracles(left_table, "left input")?;
    let right = validated_data_oracles(right_table, "right input")?;
    let output_data = validated_data_oracles(output, "join output")?;
    let expected_fields = left
        .iter()
        .chain(&right)
        .map(|(field, _)| field)
        .collect::<Vec<_>>();
    if output_data.len() != expected_fields.len() {
        return Err(join_wiring_error(format!(
            "join output has {} data fields, expected {} left/right fields",
            output_data.len(),
            expected_fields.len()
        )));
    }
    for (index, ((output_field, _), expected_field)) in
        output_data.iter().zip(expected_fields).enumerate()
    {
        if !fields_are_positionally_compatible(output_field, expected_field) {
            return Err(join_wiring_error(format!(
                "join output field {index} does not match its positional input field"
            )));
        }
    }
    if left.iter().any(|(left_field, _)| {
        right
            .iter()
            .any(|(right_field, _)| field_provenance(left_field) == field_provenance(right_field))
    }) {
        return Err(join_wiring_error(
            "left/right payload fields are not provenance-disjoint; alias self-join inputs explicitly",
        ));
    }

    let left_width = left.len();
    let selected = if use_left {
        &output_data[..left_width]
    } else {
        &output_data[left_width..]
    };
    let mut data_fields = selected.iter().cloned().collect::<IndexMap<_, _>>();
    let activator = output
        .activator_tracked_poly()
        .ok_or_else(|| join_wiring_error("join output is missing its activator"))?;
    data_fields.insert(arithmetic::ACTIVATOR_FIELD.clone(), activator);
    let schema = Some(Schema::new(
        data_fields
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>(),
    ));
    Ok(TrackedTableOracle::new(
        schema,
        data_fields,
        output.log_size(),
    ))
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
    let index_id = tracker.borrow_mut().track_base_oracle(index_oracle);
    TrackedOracle::new(Either::Left(index_id), tracker, log_size)
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        ensure_supported_join(&self.join)?;
        if self.many_to_many_gadgets().is_some() {
            let Some(PayloadStructure::GadgetPayload(payload)) =
                gadget_ready_ir.payload_for_node(&id)
            else {
                panic!("Expected gadget payload for Join gadget node");
            };

            let output = parent_plan_output_table_gadget_ready(id, gadget_ready_ir)
                .cloned()
                .unwrap_or_else(|| panic!("Expected parent-plan output table for Join gadget"));
            let left_table = parent_plan_side_table_gadget_ready(id, gadget_ready_ir, 0)
                .cloned()
                .unwrap_or_else(|| panic!("Expected parent-plan left table for Join gadget"));
            let right_table = parent_plan_side_table_gadget_ready(id, gadget_ready_ir, 1)
                .cloned()
                .unwrap_or_else(|| panic!("Expected parent-plan right table for Join gadget"));
            let Some(left_src_table) = payload.get(SRC_LEFT_LABEL).cloned() else {
                panic!("Expected src-left table for Join gadget");
            };
            let Some(right_src_table) = payload.get(SRC_RIGHT_LABEL).cloned() else {
                panic!("Expected src-right table for Join gadget");
            };
            let output_left_base =
                output_lookup_base_from_output(&output, &left_table, &right_table, true)?;
            let output_right_base =
                output_lookup_base_from_output(&output, &left_table, &right_table, false)?;
            // Purpose: Every row in the output table must consist of columns that come from some row in the left table.
            // Method: We look up table output_left in input_left
            // output left = [output activator | output keys + Output data coming from the left table + their source row number from the left table]
            // input left = [left activator | left keys + left data + normal index]
            let output_left = append_tracked_col(
                &output_left_base,
                Arc::new(Field::new(SRC_LEFT_COL_NAME, DataType::Int64, true)),
                single_data_poly_from_table(&left_src_table, "src-left")?,
            )?;

            let index_poly = index_tracked_poly(prover, &left_table);
            let input_left_base = input_lookup_base_from_table(&left_table)?;
            let input_left = append_tracked_col(
                &input_left_base,
                Arc::new(Field::new(SRC_LEFT_COL_NAME, DataType::Int64, true)),
                index_poly,
            )?;
            // Fold both sides with the same transcript challenges for this lookup.
            let left_fold_challs =
                lookup_fold_challenges_prover(prover, output_left.num_data_tracked_cols())?;
            let output_folded = fold_lookup_table_prover(&output_left, &left_fold_challs)?;
            let input_folded = fold_lookup_table_prover(&input_left, &left_fold_challs)?;

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

            let output_right = append_tracked_col(
                &output_right_base,
                Arc::new(Field::new(SRC_RIGHT_COL_NAME, DataType::Int64, true)),
                single_data_poly_from_table(&right_src_table, "src-right")?,
            )?;

            let right_index_poly = index_tracked_poly(prover, &right_table);
            let input_right_base = input_lookup_base_from_table(&right_table)?;
            let input_right = append_tracked_col(
                &input_right_base,
                Arc::new(Field::new(SRC_RIGHT_COL_NAME, DataType::Int64, true)),
                right_index_poly,
            )?;
            // Fold both sides with the same transcript challenges for this lookup.
            let right_fold_challs =
                lookup_fold_challenges_prover(prover, output_right.num_data_tracked_cols())?;
            let output_right_folded = fold_lookup_table_prover(&output_right, &right_fold_challs)?;
            let input_right_folded = fold_lookup_table_prover(&input_right, &right_fold_challs)?;
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

        let Some(output) = parent_plan_output_table_gadget_ready(id, gadget_ready_ir).cloned()
        else {
            return Ok(());
        };
        let Some(left_table) = parent_plan_side_table_gadget_ready(id, gadget_ready_ir, 0).cloned()
        else {
            return Ok(());
        };
        let Some(right_table) =
            parent_plan_side_table_gadget_ready(id, gadget_ready_ir, 1).cloned()
        else {
            return Ok(());
        };
        let Some(left_src_table) = payload.get(SRC_LEFT_LABEL).cloned() else {
            return Ok(());
        };
        let Some(right_src_table) = payload.get(SRC_RIGHT_LABEL).cloned() else {
            return Ok(());
        };

        let output_left_base =
            output_lookup_base_from_output(&output, &left_table, &right_table, true)?;
        let output_left = append_tracked_col(
            &output_left_base,
            Arc::new(Field::new(SRC_LEFT_COL_NAME, DataType::Int64, true)),
            single_data_poly_from_table(&left_src_table, "src-left")?,
        )?;
        let output_right_base =
            output_lookup_base_from_output(&output, &left_table, &right_table, false)?;
        let output_right = append_tracked_col(
            &output_right_base,
            Arc::new(Field::new(SRC_RIGHT_COL_NAME, DataType::Int64, true)),
            single_data_poly_from_table(&right_src_table, "src-right")?,
        )?;

        let index_poly = index_tracked_poly(prover, &left_table);
        let input_left_base = input_lookup_base_from_table(&left_table)?;
        let input_left = append_tracked_col(
            &input_left_base,
            Arc::new(Field::new(SRC_LEFT_COL_NAME, DataType::Int64, true)),
            index_poly,
        )?;
        let left_fold_challs =
            lookup_fold_challenges_prover(prover, output_left.num_data_tracked_cols())?;
        let output_left_folded = fold_lookup_table_prover(&output_left, &left_fold_challs)?;
        let input_left_folded = fold_lookup_table_prover(&input_left, &left_fold_challs)?;
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
        let input_right_base = input_lookup_base_from_table(&right_table)?;
        let input_right = append_tracked_col(
            &input_right_base,
            Arc::new(Field::new(SRC_RIGHT_COL_NAME, DataType::Int64, true)),
            right_index_poly,
        )?;
        let right_fold_challs =
            lookup_fold_challenges_prover(prover, output_right.num_data_tracked_cols())?;
        let output_right_folded = fold_lookup_table_prover(&output_right, &right_fold_challs)?;
        let input_right_folded = fold_lookup_table_prover(&input_right, &right_fold_challs)?;
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
        ensure_supported_join(&self.join)?;
        if self.many_to_many_gadgets().is_some() {
            let Some(PayloadStructure::GadgetPayload(payload)) =
                gadget_ready_ir.payload_for_node(&id)
            else {
                panic!("Expected gadget payload for Join gadget node");
            };

            let output = parent_plan_output_oracle_gadget_ready(id, gadget_ready_ir)
                .cloned()
                .unwrap_or_else(|| panic!("Expected parent-plan output oracle for Join gadget"));
            let left_table = parent_plan_side_oracle_gadget_ready(id, gadget_ready_ir, 0)
                .cloned()
                .unwrap_or_else(|| panic!("Expected parent-plan left oracle for Join gadget"));
            let right_table = parent_plan_side_oracle_gadget_ready(id, gadget_ready_ir, 1)
                .cloned()
                .unwrap_or_else(|| panic!("Expected parent-plan right oracle for Join gadget"));
            let Some(left_src_table) = payload.get(SRC_LEFT_LABEL).cloned() else {
                panic!("Expected src-left table for Join gadget");
            };
            let Some(right_src_table) = payload.get(SRC_RIGHT_LABEL).cloned() else {
                panic!("Expected src-right table for Join gadget");
            };
            let output_left_base =
                output_lookup_base_from_output_oracle(&output, &left_table, &right_table, true)?;
            let output_right_base =
                output_lookup_base_from_output_oracle(&output, &left_table, &right_table, false)?;
            let output_left = append_tracked_oracle(
                &output_left_base,
                Arc::new(Field::new(SRC_LEFT_COL_NAME, DataType::Int64, true)),
                single_data_oracle_from_table(&left_src_table, "src-left")?,
            )?;

            let index_oracle = index_tracked_oracle(verifier, &left_table);
            let input_left_base = input_lookup_base_from_table_oracle(&left_table)?;
            let input_left = append_tracked_oracle(
                &input_left_base,
                Arc::new(Field::new(SRC_LEFT_COL_NAME, DataType::Int64, true)),
                index_oracle,
            )?;

            // Mirror prover-side challenge reuse exactly.
            let left_fold_challs = lookup_fold_challenges_verifier(
                verifier,
                output_left.num_data_tracked_col_oracles(),
            )?;
            let output_folded = fold_lookup_table_verifier(&output_left, &left_fold_challs)?;
            let input_folded = fold_lookup_table_verifier(&input_left, &left_fold_challs)?;

            LookupPIOP::<B>::verify(
                verifier,
                LookupVerifierInput {
                    included_tracked_col_oracles: vec![output_folded],
                    super_tracked_col_oracle: input_folded,
                },
            )?;

            let output_right = append_tracked_oracle(
                &output_right_base,
                Arc::new(Field::new(SRC_RIGHT_COL_NAME, DataType::Int64, true)),
                single_data_oracle_from_table(&right_src_table, "src-right")?,
            )?;

            let right_index_oracle = index_tracked_oracle(verifier, &right_table);
            let input_right_base = input_lookup_base_from_table_oracle(&right_table)?;
            let input_right = append_tracked_oracle(
                &input_right_base,
                Arc::new(Field::new(SRC_RIGHT_COL_NAME, DataType::Int64, true)),
                right_index_oracle,
            )?;

            // Mirror prover-side challenge reuse exactly.
            let right_fold_challs = lookup_fold_challenges_verifier(
                verifier,
                output_right.num_data_tracked_col_oracles(),
            )?;
            let output_right_folded =
                fold_lookup_table_verifier(&output_right, &right_fold_challs)?;
            let input_right_folded = fold_lookup_table_verifier(&input_right, &right_fold_challs)?;

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
    pub fn new(join: Join, _requested_mode: JoinMode) -> Self {
        let bool_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::utils::bool::GadgetNode::new(),
        )));
        let nodup_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::utils::nodup::GadgetNode::default(),
        )));
        let match_pair_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::utils::match_pair_check::GadgetNode::new(),
        )));
        let gadgets = Gadgets::ManyToMany(ManyToManyGadgets {
            bool_gadget,
            nodup_gadget,
            match_pair_gadget,
        });
        Self {
            gadgets: RwLock::new(gadgets),
            join,
            join_mode: RwLock::new(JoinMode::MANY_TO_MANY),
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

    pub fn set_join_mode(&self, _requested_mode: JoinMode) {
        // `HasOne` is not a proof protocol yet: it has no child gadgets and
        // places no claims on materialized PK-side output columns. Silently
        // selecting it would therefore bypass Join soundness. Retain the
        // complete MatchPair/lookup/NoDup path until those variants acquire
        // dedicated constraints.
        let mode = JoinMode::MANY_TO_MANY;
        if let Ok(mut guard) = self.join_mode.write() {
            *guard = mode;
        }
        if let Ok(gadgets) = self.gadgets.read() {
            // Never rebuild MANY_TO_MANY children here: creating fresh child nodes would
            // change node ids and break IR payload maps keyed by existing ids.
            // The proof-supported mode must retain the children allocated at construction.
            debug_assert!(matches!(&*gadgets, Gadgets::ManyToMany(_)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GadgetNode, JoinMode, SRC_LEFT_COL_NAME, SRC_RIGHT_COL_NAME, append_tracked_col,
        ensure_supported_join, fold_lookup_table_prover, output_lookup_base_from_output,
    };
    use crate::irs::{
        ir::Ir,
        nodes::{
            IsNode, Node,
            utils::{validate_tracked_oracle_table_row_domain, validate_tracked_table_row_domain},
        },
        payloads::PayloadStructure,
        tree::Tree,
    };
    use ark_ff::Zero;
    use ark_piop::{
        DefaultSnarkBackend, SnarkBackend, arithmetic::mat_poly::mle::MLE,
        prover::structs::polynomial::TrackedPoly, test_utils::prelude_with_vars,
    };
    use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
    use datafusion_expr::{
        Expr, Join, JoinType, LogicalPlan, LogicalPlanBuilder,
        logical_plan::builder::LogicalTableSource,
    };
    use either::Either;
    use indexmap::IndexMap;
    use std::collections::HashMap;
    use std::sync::Arc;

    type B = DefaultSnarkBackend;
    type F = <B as SnarkBackend>::F;

    fn qualified_field(name: &str, qualifier: &str) -> FieldRef {
        let mut metadata = HashMap::new();
        metadata.insert("tt.qualifier".to_string(), qualifier.to_string());
        Arc::new(Field::new(name, DataType::Int64, false).with_metadata(metadata))
    }

    fn commit_table(
        prover: &mut ark_piop::prover::ArgProver<B>,
        fields: Vec<FieldRef>,
        include_activator: bool,
    ) -> arithmetic::table::TrackedTable<B> {
        let mut polys = IndexMap::new();
        for (index, field) in fields.iter().enumerate() {
            let poly = prover
                .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
                    1,
                    vec![F::from(index as u64 + 1), F::from(index as u64 + 2)],
                ))
                .expect("commit test column");
            polys.insert(field.clone(), poly);
        }
        let mut schema_fields = fields
            .iter()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        if include_activator {
            let active = prover
                .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
                    1,
                    vec![F::from(1u64), F::zero()],
                ))
                .expect("commit test activator");
            polys.insert(arithmetic::ACTIVATOR_FIELD.clone(), active);
            schema_fields.push(arithmetic::ACTIVATOR_FIELD.as_ref().clone());
        }
        arithmetic::table::TrackedTable::new(Some(Schema::new(schema_fields)), polys, 1)
    }

    fn inner_join(nullable: bool) -> Join {
        let schema = Arc::new(Schema::new(vec![Field::new(
            "key",
            DataType::Int64,
            nullable,
        )]));
        let source = Arc::new(LogicalTableSource::new(schema));
        let left = LogicalPlanBuilder::scan("left", source.clone(), None)
            .expect("build left scan")
            .build()
            .expect("finish left scan");
        let right = LogicalPlanBuilder::scan("right", source, None)
            .expect("build right scan")
            .build()
            .expect("finish right scan");
        let plan = LogicalPlanBuilder::from(left)
            .join(
                right,
                JoinType::Inner,
                (vec!["left.key"], vec!["right.key"]),
                None,
            )
            .expect("build inner join")
            .build()
            .expect("finish inner join");
        match plan {
            LogicalPlan::Join(join) => join,
            other => panic!("expected Join, got {other:?}"),
        }
    }

    fn inner_join_with_nullable_payload(nullable_payload: bool) -> Join {
        let schema = Arc::new(Schema::new(vec![
            Field::new("key", DataType::Int64, false),
            Field::new("payload", DataType::Int64, nullable_payload),
        ]));
        let source = Arc::new(LogicalTableSource::new(schema));
        let left = LogicalPlanBuilder::scan("left", source.clone(), None)
            .expect("build left scan")
            .build()
            .expect("finish left scan");
        let right = LogicalPlanBuilder::scan("right", source, None)
            .expect("build right scan")
            .build()
            .expect("finish right scan");
        let plan = LogicalPlanBuilder::from(left)
            .join(
                right,
                JoinType::Inner,
                (vec!["left.key"], vec!["right.key"]),
                None,
            )
            .expect("build inner join")
            .build()
            .expect("finish inner join");
        match plan {
            LogicalPlan::Join(join) => join,
            other => panic!("expected Join, got {other:?}"),
        }
    }

    #[test]
    fn join_proof_scope_accepts_plain_nonnullable_inner_equijoin() {
        ensure_supported_join(&inner_join(false))
            .expect("plain inner equijoin is the supported protocol scope");
    }

    #[test]
    fn join_proof_scope_rejects_unconstrained_join_shapes() {
        let mut non_inner = inner_join(false);
        non_inner.join_type = JoinType::Left;
        assert!(ensure_supported_join(&non_inner).is_err());

        let mut no_keys = inner_join(false);
        no_keys.on.clear();
        assert!(ensure_supported_join(&no_keys).is_err());

        let mut filtered = inner_join(false);
        filtered.filter = Some(datafusion_expr::lit(true));
        assert!(ensure_supported_join(&filtered).is_err());

        let mut expression_key = inner_join(false);
        expression_key.on[0].0 = Expr::Literal(datafusion_common::ScalarValue::Int64(Some(1)));
        assert!(ensure_supported_join(&expression_key).is_err());

        assert!(
            ensure_supported_join(&inner_join(true)).is_err(),
            "nullable keys must fail closed until validity bits are constrained"
        );
        assert!(
            ensure_supported_join(&inner_join_with_nullable_payload(true)).is_err(),
            "nullable non-key payloads must also fail closed: NULL and zero share an encoding"
        );
        ensure_supported_join(&inner_join_with_nullable_payload(false))
            .expect("fully nonnullable join payloads remain supported");
    }

    #[test]
    fn unsupported_has_one_modes_keep_the_complete_join_protocol() {
        let gadget =
            GadgetNode::<DefaultSnarkBackend>::new(inner_join(false), JoinMode::ONE_TO_MANY);
        assert_eq!(gadget.join_mode(), JoinMode::MANY_TO_MANY);
        assert_eq!(gadget.children().len(), 3);

        gadget.set_join_mode(JoinMode::MANY_TO_ONE);
        assert_eq!(gadget.join_mode(), JoinMode::MANY_TO_MANY);
        assert_eq!(gadget.children().len(), 3);
    }

    #[test]
    fn output_provenance_partition_is_positional_and_disjoint() {
        let (mut prover, _) = prelude_with_vars::<B>(3).expect("SRS setup");
        let mut left_metadata = HashMap::new();
        left_metadata.insert("tt.qualifier".to_string(), "left".to_string());
        left_metadata.insert("tt.pk".to_string(), "true".to_string());
        let left_field =
            Arc::new(Field::new("value", DataType::Int64, false).with_metadata(left_metadata));
        let output_left_field = qualified_field("value", "left");
        let right_field = qualified_field("value", "right");

        let left = commit_table(&mut prover, vec![left_field], false);
        let right = commit_table(&mut prover, vec![right_field.clone()], false);
        let output = commit_table(
            &mut prover,
            vec![output_left_field, right_field.clone()],
            true,
        );
        let left_output = output_lookup_base_from_output(&output, &left, &right, true)
            .expect("constraint metadata stripping must not change provenance");
        assert_eq!(left_output.num_data_tracked_cols(), 1);

        let reordered = commit_table(
            &mut prover,
            vec![right_field, qualified_field("value", "left")],
            true,
        );
        assert!(
            output_lookup_base_from_output(&reordered, &left, &right, true).is_err(),
            "a right/left payload swap must not be accepted as left/right provenance"
        );

        let mut overlapping_right_metadata = HashMap::new();
        overlapping_right_metadata.insert("tt.qualifier".to_string(), "left".to_string());
        overlapping_right_metadata.insert("tt.side_marker".to_string(), "right".to_string());
        let overlapping_right_field = Arc::new(
            Field::new("value", DataType::Int64, false).with_metadata(overlapping_right_metadata),
        );
        let overlapping_right =
            commit_table(&mut prover, vec![overlapping_right_field.clone()], false);
        let overlapping_output = commit_table(
            &mut prover,
            vec![qualified_field("value", "left"), overlapping_right_field],
            true,
        );
        assert!(
            output_lookup_base_from_output(&overlapping_output, &left, &overlapping_right, true,)
                .is_err(),
            "unaliased self-join payloads must fail closed instead of sharing one commitment"
        );
    }

    #[test]
    fn lookup_folding_and_source_columns_fail_closed_on_shape_mismatch() {
        let (mut prover, _) = prelude_with_vars::<B>(3).expect("SRS setup");
        let payload = commit_table(
            &mut prover,
            vec![qualified_field("a", "left"), qualified_field("b", "left")],
            false,
        );
        assert!(
            fold_lookup_table_prover(&payload, &[F::from(1u64)]).is_err(),
            "release builds must not truncate lookup folds with zip"
        );

        let colliding = commit_table(
            &mut prover,
            vec![qualified_field(SRC_LEFT_COL_NAME, "left")],
            false,
        );
        let source_poly: TrackedPoly<B> = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
                1,
                vec![F::zero(), F::from(1u64)],
            ))
            .expect("commit source index");
        assert!(
            append_tracked_col(
                &colliding,
                Arc::new(Field::new(SRC_LEFT_COL_NAME, DataType::Int64, false)),
                source_poly,
            )
            .is_err(),
            "the internal source index must not overwrite a same-named payload"
        );
    }

    #[test]
    fn row_domain_validation_rejects_heterogeneous_commitments() {
        let (mut prover, mut verifier) = prelude_with_vars::<B>(3).expect("SRS setup");
        let first_field = qualified_field("first", "left");
        let second_field = qualified_field("second", "left");
        let first = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
                1,
                vec![F::zero(), F::from(1u64)],
            ))
            .expect("commit first row-domain column");
        let second = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
                2,
                vec![F::zero(), F::from(1u64), F::from(2u64), F::from(3u64)],
            ))
            .expect("commit mismatched row-domain column");
        let mut cols = IndexMap::new();
        cols.insert(
            first_field.clone(),
            arithmetic::col::TrackedCol::new(first.clone(), None, Some(first_field.clone())),
        );
        cols.insert(
            second_field.clone(),
            arithmetic::col::TrackedCol::new(second.clone(), None, Some(second_field.clone())),
        );
        let malformed = arithmetic::table::TrackedTable::new_from_cols(None, cols, 1);
        assert!(
            validate_tracked_table_row_domain(&malformed, "malformed prover table").is_err(),
            "row-domain validation must not rely on debug-only constructor checks"
        );

        let hidden_activator_field = qualified_field("hidden_activator", "left");
        let hidden_activator_col = arithmetic::col::TrackedCol::SingleSegment {
            poly_bundle: arithmetic::col::PolyBundle::new(first.clone(), Some(second.clone())),
            field_ref: Some(hidden_activator_field.clone()),
        };
        let hidden_activator_table = arithmetic::table::TrackedTable::new_from_cols(
            None,
            IndexMap::from([(hidden_activator_field, hidden_activator_col)]),
            1,
        );
        assert!(
            validate_tracked_table_row_domain(&hidden_activator_table, "hidden activator table")
                .is_err(),
            "paired row activators must be validated even though flat maps omit them"
        );

        // Constants still carry an ambient Boolean-hypercube domain.  If an
        // all-one system activator is tagged with a larger domain than its
        // table, counting and lookup checks can otherwise disagree about the
        // number of physical rows even though every evaluation is `1`.
        let oversized_constant_activator =
            TrackedPoly::new(Either::Right(F::from(1u64)), 2, first.tracker());
        let constant_activator_table = arithmetic::table::TrackedTable::new_from_cols(
            None,
            IndexMap::from([
                (
                    first_field.clone(),
                    arithmetic::col::TrackedCol::new(
                        first.clone(),
                        None,
                        Some(first_field.clone()),
                    ),
                ),
                (
                    arithmetic::ACTIVATOR_FIELD.clone(),
                    arithmetic::col::TrackedCol::new(
                        oversized_constant_activator,
                        None,
                        Some(arithmetic::ACTIVATOR_FIELD.clone()),
                    ),
                ),
            ]),
            1,
        );
        assert!(
            validate_tracked_table_row_domain(
                &constant_activator_table,
                "constant activator prover table"
            )
            .is_err(),
            "a constant system activator must use the table's exact row domain"
        );

        let first_id = first.id();
        let second_id = second.id();
        let proof = prover.build_proof().expect("build commitment proof");
        verifier.set_proof(proof);
        let first_oracle = verifier
            .track_mv_com_by_id(first_id)
            .expect("track first oracle");
        let second_oracle = verifier
            .track_mv_com_by_id(second_id)
            .expect("track second oracle");
        let oversized_constant_activator_oracle =
            ark_piop::verifier::structs::oracle::TrackedOracle::new(
                Either::Right(F::from(1u64)),
                first_oracle.tracker(),
                2,
            );
        let constant_activator_oracle_table =
            arithmetic::table_oracle::TrackedTableOracle::new_from_col_oracles(
                None,
                IndexMap::from([
                    (
                        first_field.clone(),
                        arithmetic::col_oracle::TrackedColOracle::new(
                            first_oracle.clone(),
                            None,
                            Some(first_field.clone()),
                        ),
                    ),
                    (
                        arithmetic::ACTIVATOR_FIELD.clone(),
                        arithmetic::col_oracle::TrackedColOracle::new(
                            oversized_constant_activator_oracle,
                            None,
                            Some(arithmetic::ACTIVATOR_FIELD.clone()),
                        ),
                    ),
                ]),
                1,
            );
        assert!(
            validate_tracked_oracle_table_row_domain(
                &constant_activator_oracle_table,
                "constant activator verifier table"
            )
            .is_err(),
            "the verifier must reject a constant activator on the wrong row domain"
        );
        let mut oracle_cols = IndexMap::new();
        oracle_cols.insert(
            first_field.clone(),
            arithmetic::col_oracle::TrackedColOracle::new(first_oracle, None, Some(first_field)),
        );
        oracle_cols.insert(
            second_field.clone(),
            arithmetic::col_oracle::TrackedColOracle::new(second_oracle, None, Some(second_field)),
        );
        let malformed_oracles = arithmetic::table_oracle::TrackedTableOracle::new_from_col_oracles(
            None,
            oracle_cols,
            1,
        );
        assert!(
            validate_tracked_oracle_table_row_domain(
                &malformed_oracles,
                "malformed verifier table"
            )
            .is_err(),
            "the verifier must reject heterogeneous commitment domains in release builds"
        );
    }

    #[test]
    fn source_pair_nodup_uses_runtime_source_commitments() {
        let (mut prover, mut verifier) = prelude_with_vars::<B>(3).expect("SRS setup");
        let output = commit_table(&mut prover, vec![], true);
        let left_src = commit_table(
            &mut prover,
            vec![Arc::new(Field::new(
                SRC_LEFT_COL_NAME,
                DataType::Int64,
                false,
            ))],
            false,
        );
        let right_src = commit_table(
            &mut prover,
            vec![Arc::new(Field::new(
                SRC_RIGHT_COL_NAME,
                DataType::Int64,
                false,
            ))],
            false,
        );
        let sentinel = commit_table(
            &mut prover,
            vec![Arc::new(Field::new("sentinel", DataType::Int64, false))],
            true,
        );

        let gadget = Arc::new(GadgetNode::<B>::new(
            inner_join(false),
            JoinMode::MANY_TO_MANY,
        ));
        let root = Arc::new(Node::Gadget(gadget.clone()));
        let tree = Tree::new_from_root(root);
        let mut prover_ir: crate::prover::irs::VirtualizedIr<B> = Ir::new_empty(tree.clone());
        let nodup_id = gadget
            .many_to_many_gadgets()
            .expect("many-to-many children")
            .nodup_gadget
            .id();
        prover_ir.set_payload_for_node(
            nodup_id,
            Some(PayloadStructure::GadgetPayload(IndexMap::from([(
                crate::irs::nodes::utils::nodup::INPUT_LABEL.to_string(),
                sentinel.clone(),
            )]))),
        );
        let same_named_right_source = commit_table(
            &mut prover,
            vec![Arc::new(Field::new(
                SRC_LEFT_COL_NAME,
                DataType::Int64,
                false,
            ))],
            false,
        );
        gadget
            .wire_prover_nodup_payload(&output, &left_src, &same_named_right_source, &mut prover_ir)
            .expect("source-pair coordinates are rebound to distinct internal names");
        let PayloadStructure::GadgetPayload(rebound) = prover_ir
            .payload_for_node(&nodup_id)
            .expect("rebound NoDup payload")
        else {
            panic!("expected gadget payload")
        };
        let rebound = rebound
            .get(crate::irs::nodes::utils::nodup::INPUT_LABEL)
            .expect("rebound NoDup input");
        assert_eq!(rebound.num_data_tracked_cols(), 2);
        assert_eq!(
            rebound
                .tracked_col_by_name(SRC_RIGHT_COL_NAME)
                .expect("distinct right source coordinate")
                .data_tracked_poly()
                .id(),
            same_named_right_source
                .tracked_col_by_name(SRC_LEFT_COL_NAME)
                .expect("same-named source payload")
                .data_tracked_poly()
                .id()
        );
        let mismatched_source_field =
            Arc::new(Field::new(SRC_LEFT_COL_NAME, DataType::Int64, false));
        let mismatched_source_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
                2,
                vec![F::zero(), F::from(1u64), F::from(2u64), F::from(3u64)],
            ))
            .expect("commit mismatched source domain");
        let mismatched_source = arithmetic::table::TrackedTable::new(
            Some(Schema::new(vec![mismatched_source_field.as_ref().clone()])),
            IndexMap::from([(mismatched_source_field, mismatched_source_poly)]),
            2,
        );
        assert!(
            gadget
                .wire_prover_nodup_payload(&output, &mismatched_source, &right_src, &mut prover_ir,)
                .is_err(),
            "source indices on a different output row domain must fail closed"
        );
        gadget
            .wire_prover_nodup_payload(&output, &left_src, &right_src, &mut prover_ir)
            .expect("bind runtime source pairs to NoDup");
        let PayloadStructure::GadgetPayload(bound) = prover_ir
            .payload_for_node(&nodup_id)
            .expect("wired NoDup payload")
        else {
            panic!("expected gadget payload")
        };
        let bound = bound
            .get(crate::irs::nodes::utils::nodup::INPUT_LABEL)
            .expect("NoDup input");
        assert_eq!(
            bound
                .activator_tracked_poly()
                .expect("bound activator")
                .id(),
            output
                .activator_tracked_poly()
                .expect("output activator")
                .id()
        );
        assert_eq!(
            bound
                .tracked_col_by_name(SRC_LEFT_COL_NAME)
                .expect("bound left source")
                .data_tracked_poly()
                .id(),
            left_src
                .tracked_col_by_name(SRC_LEFT_COL_NAME)
                .expect("left source")
                .data_tracked_poly()
                .id()
        );
        assert_eq!(
            bound
                .tracked_col_by_name(SRC_RIGHT_COL_NAME)
                .expect("bound right source")
                .data_tracked_poly()
                .id(),
            right_src
                .tracked_col_by_name(SRC_RIGHT_COL_NAME)
                .expect("right source")
                .data_tracked_poly()
                .id()
        );

        let proof = prover.build_proof().expect("build commitment proof");
        verifier.set_proof(proof);
        let output_oracle =
            arithmetic::table_oracle::TrackedTableOracle::from_tracked_table(output, &mut verifier)
                .expect("track output");
        let left_src_oracle = arithmetic::table_oracle::TrackedTableOracle::from_tracked_table(
            left_src,
            &mut verifier,
        )
        .expect("track left source");
        let right_src_oracle = arithmetic::table_oracle::TrackedTableOracle::from_tracked_table(
            right_src,
            &mut verifier,
        )
        .expect("track right source");
        let sentinel_oracle = arithmetic::table_oracle::TrackedTableOracle::from_tracked_table(
            sentinel,
            &mut verifier,
        )
        .expect("track sentinel");
        let same_named_right_oracle =
            arithmetic::table_oracle::TrackedTableOracle::from_tracked_table(
                same_named_right_source,
                &mut verifier,
            )
            .expect("track same-named right source");
        let mut verifier_ir: crate::verifier::irs::VirtualizedIr<B> = Ir::new_empty(tree);
        verifier_ir.set_payload_for_node(
            nodup_id,
            Some(PayloadStructure::GadgetPayload(IndexMap::from([(
                crate::irs::nodes::utils::nodup::INPUT_LABEL.to_string(),
                sentinel_oracle,
            )]))),
        );
        gadget
            .wire_verifier_nodup_payload(
                &output_oracle,
                &left_src_oracle,
                &same_named_right_oracle,
                &mut verifier_ir,
            )
            .expect("verifier rebinds source-pair coordinates to distinct names");
        let PayloadStructure::GadgetPayload(rebound) = verifier_ir
            .payload_for_node(&nodup_id)
            .expect("rebound verifier NoDup payload")
        else {
            panic!("expected verifier gadget payload")
        };
        let rebound = rebound
            .get(crate::irs::nodes::utils::nodup::INPUT_LABEL)
            .expect("rebound verifier NoDup input");
        assert_eq!(rebound.num_data_tracked_col_oracles(), 2);
        assert_eq!(
            rebound
                .tracked_col_oracle_by_name(SRC_RIGHT_COL_NAME)
                .expect("distinct right source oracle")
                .data_tracked_oracle()
                .id(),
            same_named_right_oracle
                .tracked_col_oracle_by_name(SRC_LEFT_COL_NAME)
                .expect("same-named source oracle payload")
                .data_tracked_oracle()
                .id()
        );
        gadget
            .wire_verifier_nodup_payload(
                &output_oracle,
                &left_src_oracle,
                &right_src_oracle,
                &mut verifier_ir,
            )
            .expect("bind runtime source-pair oracles to NoDup");
        let PayloadStructure::GadgetPayload(bound) = verifier_ir
            .payload_for_node(&nodup_id)
            .expect("wired verifier NoDup payload")
        else {
            panic!("expected verifier gadget payload")
        };
        let bound = bound
            .get(crate::irs::nodes::utils::nodup::INPUT_LABEL)
            .expect("verifier NoDup input");
        assert_eq!(
            bound
                .activator_tracked_poly()
                .expect("bound activator")
                .id(),
            output_oracle
                .activator_tracked_poly()
                .expect("output activator")
                .id()
        );
        assert_eq!(
            bound
                .tracked_col_oracle_by_name(SRC_LEFT_COL_NAME)
                .expect("bound left source oracle")
                .data_tracked_oracle()
                .id(),
            left_src_oracle
                .tracked_col_oracle_by_name(SRC_LEFT_COL_NAME)
                .expect("left source oracle")
                .data_tracked_oracle()
                .id()
        );
        assert_eq!(
            bound
                .tracked_col_oracle_by_name(SRC_RIGHT_COL_NAME)
                .expect("bound right source oracle")
                .data_tracked_oracle()
                .id(),
            right_src_oracle
                .tracked_col_oracle_by_name(SRC_RIGHT_COL_NAME)
                .expect("right source oracle")
                .data_tracked_oracle()
                .id()
        );
    }
}

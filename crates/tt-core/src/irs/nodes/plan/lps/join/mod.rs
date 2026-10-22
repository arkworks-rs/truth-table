use crate::irs::nodes::utils::{commit_with_tracker, field_to_usize, track_next_committed};
use std::{
    any::Any,
    collections::BTreeSet,
    sync::{Arc, Mutex, RwLock, Weak},
};

use crate::irs::{
    nodes::{
        IsLpNode, IsNode, IsPlanNode, Node, ProverNodeOps, VerifierNodeOps,
        plan::lps::join::gadget as join_gadget,
    },
    payloads::PayloadStructure,
    tree::Tree,
};
type JoinOnNodes<B> = Vec<(Arc<Node<B>>, Arc<Node<B>>)>;

use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, ROW_ID_COL_NAME, is_system_column};
use ark_piop::SnarkBackend;
use datafusion::arrow::array::Array;
use datafusion::arrow::datatypes::Schema;
use datafusion_common::Column;
use datafusion_expr::{Join, LogicalPlan};
use indexmap::IndexMap;
pub mod gadget;
mod hints;
pub mod modes;

#[allow(clippy::type_complexity)]
pub struct LpNode<B>
where
    B: SnarkBackend,
{
    left: Arc<Node<B>>,
    right: Arc<Node<B>>,
    on: Vec<(Arc<Node<B>>, Arc<Node<B>>)>,
    filter: Option<Arc<Node<B>>>,
    gadget: Arc<Node<B>>,
    join: Join,
    // Decides both the materialization policy and the gadget's protocol.
    // Interior-mutable so the `PkFkSpecialization` pp_optimizer rule can
    // upgrade it after ingestion, through `set_join_mode`.
    join_mode: RwLock<modes::JoinMode>,
    // Cached by `output()`: a fully materialized join rebuilds its contiguous
    // activator from this count in `add_virtual_witness`.
    full_materialized_active_rows: Mutex<Option<usize>>,
}

impl<B: SnarkBackend> LpNode<B> {
    const PK_METADATA_KEY: &'static str = "tt.pk";
    const FK_REF_TABLE_METADATA_KEY: &'static str = "tt.fk.ref_table";
    const FK_REF_COLUMNS_METADATA_KEY: &'static str = "tt.fk.ref_columns";

    fn join_mode(&self) -> modes::JoinMode {
        self.join_mode
            .read()
            .map(|guard| *guard)
            .unwrap_or(modes::JoinMode::MANY_TO_MANY)
    }

    /// Sets the mode here and on the inner gadget, so the plan-side
    /// materialization policy and the gadget-side protocol stay in sync.
    pub fn set_join_mode(&self, mode: modes::JoinMode) {
        if let Ok(mut guard) = self.join_mode.write() {
            *guard = mode;
        }
        if let Node::Gadget(gadget) = self.gadget.as_ref() {
            let any = gadget.as_ref() as &dyn Any;
            if let Some(join_gadget) = any.downcast_ref::<gadget::GadgetNode<B>>() {
                join_gadget.set_join_mode(mode);
            }
        }
    }

    fn should_fully_materialize(&self) -> bool {
        // Must match the gadget's protocol: MANY_TO_MANY materializes the
        // whole output, every other mode (HasOne) only the PK side.
        self.join_mode() == modes::JoinMode::MANY_TO_MANY
    }

    fn fk_side_input(&self) -> Option<&Arc<Node<B>>> {
        match self.join_mode() {
            // Left is the unique side, right the FK side.
            modes::JoinMode::ONE_TO_MANY => Some(&self.right),
            // Right is the unique side, left the FK side.
            modes::JoinMode::MANY_TO_ONE => Some(&self.left),
            // The same side `output()` keeps virtual.
            modes::JoinMode::ONE_TO_ONE => Some(&self.right),
            modes::JoinMode::MANY_TO_MANY => None,
        }
    }

    fn cache_full_materialized_active_rows(&self, n: usize) {
        if let Ok(mut slot) = self.full_materialized_active_rows.lock() {
            *slot = Some(n);
        }
    }

    fn cached_full_materialized_active_rows(&self) -> usize {
        self.full_materialized_active_rows
            .lock()
            .ok()
            .and_then(|slot| *slot)
            .expect("full-materialized join active-row count was not cached during output()")
    }

    fn field_names_prover(table: &arithmetic::table::TrackedTable<B>) -> BTreeSet<String> {
        table
            .tracked_polys_iter()
            .map(|(field, _)| field.name().to_string())
            .collect()
    }

    fn field_names_verifier(
        table: &arithmetic::table_oracle::TrackedTableOracle<B>,
    ) -> BTreeSet<String> {
        table
            .tracked_oracles_iter()
            .map(|(field, _)| field.name().to_string())
            .collect()
    }

    fn ordered_fields_prover(
        table: &arithmetic::table::TrackedTable<B>,
    ) -> Vec<datafusion::arrow::datatypes::FieldRef> {
        match table.schema_ref() {
            Some(schema) => schema
                .fields()
                .iter()
                .map(|field| Arc::new(field.as_ref().clone()))
                .collect(),
            None => table.tracked_polys().keys().cloned().collect(),
        }
    }

    fn ordered_fields_verifier(
        table: &arithmetic::table_oracle::TrackedTableOracle<B>,
    ) -> Vec<datafusion::arrow::datatypes::FieldRef> {
        match table.schema_ref() {
            Some(schema) => schema
                .fields()
                .iter()
                .map(|field| Arc::new(field.as_ref().clone()))
                .collect(),
            None => table.tracked_oracles().keys().cloned().collect(),
        }
    }

    fn merge_partial_output_prover(
        current_table: &arithmetic::table::TrackedTable<B>,
        fk_table: &arithmetic::table::TrackedTable<B>,
    ) -> arithmetic::table::TrackedTable<B> {
        let current_cols = current_table.tracked_polys();
        let fk_cols = fk_table.tracked_polys();
        let mut merged_polys = IndexMap::new();

        // Column order of the DataFrame hint: FK-side columns, then PK-side
        // columns, then activator and row_id.
        for field in Self::ordered_fields_prover(fk_table) {
            if field.name() == ACTIVATOR_COL_NAME || field.name() == ROW_ID_COL_NAME {
                continue;
            }
            if let Some(poly) = fk_cols.get(&field) {
                merged_polys.insert(field.clone(), poly.clone());
            }
        }
        for field in Self::ordered_fields_prover(current_table) {
            if field.name() == ACTIVATOR_COL_NAME || field.name() == ROW_ID_COL_NAME {
                continue;
            }
            if merged_polys
                .keys()
                .any(|existing| existing.name() == field.name())
            {
                continue;
            }
            if let Some(poly) = current_cols.get(&field) {
                merged_polys.insert(field.clone(), poly.clone());
            }
        }

        // The output keeps one row per FK-side row (PKFKJoin), so its
        // activator is the FK side's.
        if let Some((field, poly)) = fk_cols
            .iter()
            .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
            .map(|(field, poly)| (field.clone(), poly.clone()))
        {
            merged_polys.insert(field, poly);
        }
        if let Some((field, poly)) = fk_cols
            .iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
            .map(|(field, poly)| (field.clone(), poly.clone()))
            .or_else(|| {
                current_cols
                    .iter()
                    .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
                    .map(|(field, poly)| (field.clone(), poly.clone()))
            })
        {
            merged_polys.insert(field, poly);
        }

        let metadata = current_table
            .schema_ref()
            .map(|s| s.metadata().clone())
            .or_else(|| fk_table.schema_ref().map(|s| s.metadata().clone()))
            .unwrap_or_default();
        let fields = merged_polys
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        let schema = Some(Schema::new_with_metadata(fields, metadata));

        let log_size = match (current_table.log_size(), fk_table.log_size()) {
            (0, other) => other,
            (current, 0) => current,
            (current, input) => {
                debug_assert_eq!(current, input, "Join log sizes should match FK-side input");
                current
            }
        };

        arithmetic::table::TrackedTable::new(schema, merged_polys, log_size)
    }

    fn merge_partial_output_verifier(
        current_table: &arithmetic::table_oracle::TrackedTableOracle<B>,
        fk_table: &arithmetic::table_oracle::TrackedTableOracle<B>,
    ) -> arithmetic::table_oracle::TrackedTableOracle<B> {
        let current_cols = current_table.tracked_oracles();
        let fk_cols = fk_table.tracked_oracles();
        let mut merged_oracles = IndexMap::new();

        for field in Self::ordered_fields_verifier(fk_table) {
            if field.name() == ACTIVATOR_COL_NAME || field.name() == ROW_ID_COL_NAME {
                continue;
            }
            if let Some(oracle) = fk_cols.get(&field) {
                merged_oracles.insert(field.clone(), oracle.clone());
            }
        }
        for field in Self::ordered_fields_verifier(current_table) {
            if field.name() == ACTIVATOR_COL_NAME || field.name() == ROW_ID_COL_NAME {
                continue;
            }
            if merged_oracles
                .keys()
                .any(|existing| existing.name() == field.name())
            {
                continue;
            }
            if let Some(oracle) = current_cols.get(&field) {
                merged_oracles.insert(field.clone(), oracle.clone());
            }
        }

        // The output keeps one row per FK-side row (PKFKJoin), so its
        // activator is the FK side's.
        if let Some((field, oracle)) = fk_cols
            .iter()
            .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
            .map(|(field, oracle)| (field.clone(), oracle.clone()))
        {
            merged_oracles.insert(field, oracle);
        }
        if let Some((field, oracle)) = fk_cols
            .iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
            .map(|(field, oracle)| (field.clone(), oracle.clone()))
            .or_else(|| {
                current_cols
                    .iter()
                    .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
                    .map(|(field, oracle)| (field.clone(), oracle.clone()))
            })
        {
            merged_oracles.insert(field, oracle);
        }

        let metadata = current_table
            .schema_ref()
            .map(|s| s.metadata().clone())
            .or_else(|| fk_table.schema_ref().map(|s| s.metadata().clone()))
            .unwrap_or_default();
        let fields = merged_oracles
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        let schema = Some(Schema::new_with_metadata(fields, metadata));

        let log_size = match (current_table.log_size(), fk_table.log_size()) {
            (0, other) => other,
            (current, 0) => current,
            (current, input) => {
                debug_assert_eq!(current, input, "Join log sizes should match FK-side input");
                current
            }
        };

        arithmetic::table_oracle::TrackedTableOracle::new(schema, merged_oracles, log_size)
    }

    fn preserve_constraints_for_field(
        mode: modes::JoinMode,
        field_name: &str,
        left_names: &BTreeSet<String>,
        right_names: &BTreeSet<String>,
    ) -> bool {
        match mode {
            // left unique, right is FK-preserved side
            modes::JoinMode::ONE_TO_MANY => right_names.contains(field_name),
            // right unique, left is FK-preserved side
            modes::JoinMode::MANY_TO_ONE => left_names.contains(field_name),
            // no duplication from join cardinality
            modes::JoinMode::ONE_TO_ONE => {
                left_names.contains(field_name) || right_names.contains(field_name)
            }
            // both sides can duplicate
            modes::JoinMode::MANY_TO_MANY => false,
        }
    }

    fn rewrite_constraint_metadata(
        field: &datafusion::arrow::datatypes::FieldRef,
        preserve: bool,
    ) -> datafusion::arrow::datatypes::FieldRef {
        if is_system_column(field.name()) {
            return field.clone();
        }
        let mut updated = field.as_ref().clone();
        let mut metadata = updated.metadata().clone();
        if !preserve {
            metadata.remove(Self::PK_METADATA_KEY);
            metadata.remove(Self::FK_REF_TABLE_METADATA_KEY);
            metadata.remove(Self::FK_REF_COLUMNS_METADATA_KEY);
        }
        updated = updated.with_metadata(metadata);
        Arc::new(updated)
    }

    fn update_constraints_prover(
        table: &arithmetic::table::TrackedTable<B>,
        mode: modes::JoinMode,
        left_names: &BTreeSet<String>,
        right_names: &BTreeSet<String>,
    ) -> arithmetic::table::TrackedTable<B> {
        let mut updated_polys = IndexMap::new();
        for (field, poly) in table.tracked_polys_iter() {
            let preserve =
                Self::preserve_constraints_for_field(mode, field.name(), left_names, right_names);
            let updated_field = Self::rewrite_constraint_metadata(&field, preserve);
            updated_polys.insert(updated_field, poly);
        }
        let schema = table.schema_ref().map(|schema| {
            let fields = updated_polys.keys().cloned().collect::<Vec<_>>();
            Schema::new_with_metadata(fields, schema.metadata().clone())
        });
        arithmetic::table::TrackedTable::new(schema, updated_polys, table.log_size())
    }

    fn update_constraints_verifier(
        table: &arithmetic::table_oracle::TrackedTableOracle<B>,
        mode: modes::JoinMode,
        left_names: &BTreeSet<String>,
        right_names: &BTreeSet<String>,
    ) -> arithmetic::table_oracle::TrackedTableOracle<B> {
        let mut updated_oracles = IndexMap::new();
        for (field, oracle) in table.tracked_oracles_iter() {
            let preserve =
                Self::preserve_constraints_for_field(mode, field.name(), left_names, right_names);
            let updated_field = Self::rewrite_constraint_metadata(&field, preserve);
            updated_oracles.insert(updated_field, oracle);
        }
        let schema = table.schema_ref().map(|schema| {
            let fields = updated_oracles.keys().cloned().collect::<Vec<_>>();
            Schema::new_with_metadata(fields, schema.metadata().clone())
        });
        arithmetic::table_oracle::TrackedTableOracle::new(schema, updated_oracles, table.log_size())
    }
}

impl<B: SnarkBackend> IsNode<B> for LpNode<B> {
    fn name(&self) -> String {
        "Join".to_string()
    }

    fn display(&self) -> String {
        let on_pairs = if self.on.is_empty() {
            "none".to_string()
        } else {
            self.on
                .iter()
                .map(|(left, right)| format!("{}={}", left.name(), right.name()))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let filter = self
            .filter
            .as_ref()
            .map(|node| node.name())
            .unwrap_or_else(|| "none".to_string());
        format!(
            "Join\nLeft: {}, Right: {}, type: {:?}, on: {}, filter: {}",
            self.left.name(),
            self.right.name(),
            self.join.join_type,
            on_pairs,
            filter,
        )
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        let mut children = vec![self.left.clone(), self.right.clone()];
        if let Some(filter) = &self.filter {
            children.push(filter.clone());
        }
        self.on.iter().for_each(|(l, r)| {
            children.push(l.clone());
            children.push(r.clone());
        });
        children.push(self.gadget.clone());
        children
    }
}
impl<B: SnarkBackend> ProverNodeOps<B> for LpNode<B> {
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let left_names = virtualized_ir
            .payload_for_node(&self.left.id())
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(Self::field_names_prover(table)),
                _ => None,
            })
            .unwrap_or_default();
        let right_names = virtualized_ir
            .payload_for_node(&self.right.id())
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(Self::field_names_prover(table)),
                _ => None,
            })
            .unwrap_or_default();
        if self.should_fully_materialize() {
            let current_table = virtualized_ir
                .payload_for_node(&id)
                .and_then(|payload| match payload {
                    PayloadStructure::PlanPayload(table) => Some(table.clone()),
                    _ => None,
                })
                .unwrap_or_default();

            let Some(tracker_rc) = current_table
                .tracked_polys_iter()
                .next()
                .map(|(_, poly)| poly.tracker())
            else {
                return Ok(());
            };
            // The output activator is the public C_{µ,s} (paper PIOP 18, step 1);
            // `s` is committed, so it is in the transcript.
            let active_rows = self.cached_full_materialized_active_rows();
            commit_with_tracker(&tracker_rc, 0, vec![B::F::from(active_rows as u64)])?;
            let contig_activator = tracker_rc
                .borrow_mut()
                .get_or_build_contig_one_poly(current_table.log_size(), active_rows)?;
            let updated_table = append_activator_prover(&current_table, contig_activator);
            let updated_table = Self::update_constraints_prover(
                &updated_table,
                self.join_mode(),
                &left_names,
                &right_names,
            );
            virtualized_ir
                .set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
            return Ok(());
        }

        let Some(fk_input) = self.fk_side_input() else {
            return Ok(());
        };

        let fk_table = match virtualized_ir.payload_for_node(&fk_input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        let current_table = virtualized_ir
            .payload_for_node(&id)
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(table.clone()),
                _ => None,
            })
            .unwrap_or_default();

        let updated_table = Self::merge_partial_output_prover(&current_table, &fk_table);
        let updated_table = Self::update_constraints_prover(
            &updated_table,
            self.join_mode(),
            &left_names,
            &right_names,
        );
        // Every output column lives on the FK-side row domain.
        debug_assert!(
            updated_table
                .tracked_polys_iter()
                .all(|(_, poly)| poly.log_size() == updated_table.log_size()),
            "Join output contains columns from mixed log-size domains (prover)"
        );
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let output_table = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Join output payload missing"),
        };
        let left_table = match virtualized_ir.payload_for_node(&self.left.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Join left payload missing"),
        };
        let right_table = match virtualized_ir.payload_for_node(&self.right.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Join right payload missing"),
        };

        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(join_gadget::LEFT_LABEL.to_string(), left_table);
        gadget_payload.insert(join_gadget::RIGHT_LABEL.to_string(), right_table);
        gadget_payload.insert(join_gadget::OUTPUT_LABEL.to_string(), output_table);
        virtualized_ir.set_payload_for_node(
            self.gadget.id(),
            Some(PayloadStructure::GadgetPayload(gadget_payload)),
        );

        Ok(())
    }
    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let left_hint_df = match planned_ir.payload_for_node(&self.left.id()) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df,
            _ => return Ok(()),
        };
        let right_hint_df = match planned_ir.payload_for_node(&self.right.id()) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df,
            _ => return Ok(()),
        };
        let output_hint_df = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df,
            _ => return Ok(()),
        };

        let mut gadget_payload = match planned_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(
            join_gadget::LEFT_LABEL.to_string(),
            left_hint_df.as_virtual_view(),
        );
        gadget_payload.insert(
            join_gadget::RIGHT_LABEL.to_string(),
            right_hint_df.as_virtual_view(),
        );
        gadget_payload.insert(
            join_gadget::OUTPUT_LABEL.to_string(),
            output_hint_df.as_virtual_view(),
        );

        planned_ir.set_payload_for_node(
            self.gadget.id(),
            Some(PayloadStructure::GadgetPayload(gadget_payload)),
        );
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for LpNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        Some(self.gadget.as_ref().clone())
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsProverPlanNode<B> for LpNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let left_hint_df = match self.left.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsProverPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Join left input cannot be a gadget node"),
        };
        let right_hint_df = match self.right.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsProverPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Join right input cannot be a gadget node"),
        };
        let full_materialization = self.should_fully_materialize();
        let joined = if full_materialization {
            hints::build_output_dataframe(
                left_hint_df.data_frame().clone(),
                right_hint_df.data_frame().clone(),
                &self.join,
            )
        } else {
            // Partial mode (HasOne): the output keeps the FK-side row domain and
            // only the PK-side columns are materialized, so virtual and
            // materialized columns share one log size.
            hints::build_partial_output_dataframe(
                left_hint_df.data_frame().clone(),
                right_hint_df.data_frame().clone(),
                &self.join,
                self.join_mode(),
            )
        };

        if self.should_fully_materialize() {
            self.cache_full_materialized_active_rows(active_row_count_from_dataframe(&joined));
        }

        let left_fields = left_hint_df
            .data_frame()
            .schema()
            .fields()
            .iter()
            .map(|field| field.name().clone())
            .collect::<std::collections::BTreeSet<_>>();
        let right_fields = right_hint_df
            .data_frame()
            .schema()
            .fields()
            .iter()
            .map(|field| field.name().clone())
            .collect::<std::collections::BTreeSet<_>>();

        let should_materialize: IndexMap<_, _> = joined
            .schema()
            .fields()
            .iter()
            .map(|field| {
                let name = field.name();
                // `__row_id__` is never materialized, and must not reach the
                // side-membership check below: the verifier's side schema (the
                // oracle schema) has no `__row_id__` while the prover's (the
                // parquet schema) does, so their tracker ids would diverge.
                let mat = if name == ROW_ID_COL_NAME {
                    false
                } else if full_materialization {
                    // Every data column; the activator is the contiguous one
                    // built in `add_virtual_witness`.
                    name != ACTIVATOR_COL_NAME
                } else if name == ACTIVATOR_COL_NAME {
                    // Partial path (HasOne): the output activator is the FK
                    // side's, copied in by `add_virtual_witness`, never a
                    // prover-chosen commitment.
                    false
                } else {
                    // Partial path (HasOne): only the PK side's data is
                    // materialized; the FK-side columns stay virtual.
                    match self.join_mode() {
                        modes::JoinMode::ONE_TO_MANY => left_fields.contains(name),
                        modes::JoinMode::MANY_TO_ONE => right_fields.contains(name),
                        // Right is the virtual, FK-preserved side.
                        modes::JoinMode::ONE_TO_ONE => left_fields.contains(name),
                        modes::JoinMode::MANY_TO_MANY => true,
                    }
                };
                (field.clone(), mat)
            })
            .collect();
        crate::irs::nodes::hints::HintDF::new(joined, should_materialize)
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for LpNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let left_hint_df = match self.left.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Join left input cannot be a gadget node"),
        };
        let right_hint_df = match self.right.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Join right input cannot be a gadget node"),
        };
        let full_materialization = self.should_fully_materialize();
        let joined = if full_materialization {
            build_output_dataframe_verifier_light(
                left_hint_df.data_frame().clone(),
                right_hint_df.data_frame().clone(),
                &self.join,
            )
        } else {
            build_partial_output_dataframe_verifier_light(
                left_hint_df.data_frame().clone(),
                right_hint_df.data_frame().clone(),
                &self.join,
                self.join_mode(),
            )
        };

        let left_fields = left_hint_df
            .data_frame()
            .schema()
            .fields()
            .iter()
            .map(|field| field.name().clone())
            .collect::<std::collections::BTreeSet<_>>();
        let right_fields = right_hint_df
            .data_frame()
            .schema()
            .fields()
            .iter()
            .map(|field| field.name().clone())
            .collect::<std::collections::BTreeSet<_>>();

        let should_materialize: IndexMap<_, _> = joined
            .schema()
            .fields()
            .iter()
            .map(|field| {
                let name = field.name();
                // Same policy as the prover's `output()`; see there for why
                // `__row_id__` skips the side-membership check.
                let mat = if name == ROW_ID_COL_NAME {
                    false
                } else if full_materialization {
                    name != ACTIVATOR_COL_NAME
                } else if name == ACTIVATOR_COL_NAME {
                    false
                } else {
                    match self.join_mode() {
                        modes::JoinMode::ONE_TO_MANY => left_fields.contains(name),
                        modes::JoinMode::MANY_TO_ONE => right_fields.contains(name),
                        modes::JoinMode::ONE_TO_ONE => left_fields.contains(name),
                        modes::JoinMode::MANY_TO_MANY => true,
                    }
                };
                (field.clone(), mat)
            })
            .collect();
        crate::irs::nodes::hints::HintDF::new(joined, should_materialize)
    }
}

fn build_output_dataframe_verifier_light(
    left_df: datafusion::prelude::DataFrame,
    right_df: datafusion::prelude::DataFrame,
    join: &Join,
) -> datafusion::prelude::DataFrame {
    let left_df_fallback = left_df.clone();
    let right_df_fallback = right_df.clone();

    let joined = match left_df.join_on(
        right_df,
        join.join_type,
        vec![datafusion_expr::lit(true).eq(datafusion_expr::lit(true))],
    ) {
        Ok(df) => df,
        Err(_) => {
            return hints::build_output_dataframe(left_df_fallback, right_df_fallback, join);
        }
    };

    let mut projection_exprs = Vec::new();
    for (qualifier, field) in joined.schema().iter() {
        if field.name() == ACTIVATOR_COL_NAME || field.name() == ROW_ID_COL_NAME {
            continue;
        }
        projection_exprs.push(datafusion_expr::Expr::Column(Column::new(
            qualifier.cloned(),
            field.name(),
        )));
    }
    projection_exprs.push(datafusion_expr::lit(true).alias(ACTIVATOR_COL_NAME));
    projection_exprs.push(datafusion_expr::lit(0_i64).alias(ROW_ID_COL_NAME));

    joined
        .select(projection_exprs)
        .expect("join verifier output projection should succeed")
}

fn build_partial_output_dataframe_verifier_light(
    left_df: datafusion::prelude::DataFrame,
    right_df: datafusion::prelude::DataFrame,
    join: &Join,
    mode: modes::JoinMode,
) -> datafusion::prelude::DataFrame {
    let left_df_fallback = left_df.clone();
    let right_df_fallback = right_df.clone();

    let fk_is_left = matches!(mode, modes::JoinMode::MANY_TO_ONE);
    let (fk_df, pk_df) = if fk_is_left {
        (left_df, right_df)
    } else {
        (right_df, left_df)
    };

    let joined = match fk_df.join_on(
        pk_df,
        datafusion_expr::JoinType::Left,
        vec![datafusion_expr::lit(true).eq(datafusion_expr::lit(true))],
    ) {
        Ok(df) => df,
        Err(_) => {
            return hints::build_partial_output_dataframe(
                left_df_fallback,
                right_df_fallback,
                join,
                mode,
            );
        }
    };

    let mut projection_exprs = Vec::new();
    let mut fk_row_id_expr: Option<datafusion_expr::Expr> = None;
    for (qualifier, field) in joined.schema().iter() {
        if field.name() == ROW_ID_COL_NAME && fk_row_id_expr.is_none() {
            fk_row_id_expr = Some(datafusion_expr::Expr::Column(Column::new(
                qualifier.cloned(),
                field.name(),
            )));
        }
        if field.name() == ACTIVATOR_COL_NAME || field.name() == ROW_ID_COL_NAME {
            continue;
        }
        projection_exprs.push(datafusion_expr::Expr::Column(Column::new(
            qualifier.cloned(),
            field.name(),
        )));
    }
    projection_exprs.push(datafusion_expr::lit(true).alias(ACTIVATOR_COL_NAME));
    projection_exprs.push(
        fk_row_id_expr
            .unwrap_or_else(|| datafusion_expr::lit(0_i64))
            .alias(ROW_ID_COL_NAME),
    );

    joined
        .select(projection_exprs)
        .expect("partial join verifier output projection should succeed")
}

impl<B: SnarkBackend> VerifierNodeOps<B> for LpNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let left_hint_df = match planned_ir.payload_for_node(&self.left.id()) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df,
            _ => return Ok(()),
        };
        let right_hint_df = match planned_ir.payload_for_node(&self.right.id()) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df,
            _ => return Ok(()),
        };
        let output_hint_df = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df,
            _ => return Ok(()),
        };

        let mut gadget_payload = match planned_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(
            join_gadget::LEFT_LABEL.to_string(),
            left_hint_df.as_virtual_view(),
        );
        gadget_payload.insert(
            join_gadget::RIGHT_LABEL.to_string(),
            right_hint_df.as_virtual_view(),
        );
        gadget_payload.insert(
            join_gadget::OUTPUT_LABEL.to_string(),
            output_hint_df.as_virtual_view(),
        );

        planned_ir.set_payload_for_node(
            self.gadget.id(),
            Some(PayloadStructure::GadgetPayload(gadget_payload)),
        );
        Ok(())
    }
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let left_names = virtualized_ir
            .payload_for_node(&self.left.id())
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(Self::field_names_verifier(table)),
                _ => None,
            })
            .unwrap_or_default();
        let right_names = virtualized_ir
            .payload_for_node(&self.right.id())
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(Self::field_names_verifier(table)),
                _ => None,
            })
            .unwrap_or_default();
        if self.should_fully_materialize() {
            let current_table = virtualized_ir
                .payload_for_node(&id)
                .and_then(|payload| match payload {
                    PayloadStructure::PlanPayload(table) => Some(table.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            let Some(tracker_rc) = current_table
                .tracked_oracles_iter()
                .next()
                .map(|(_, oracle)| oracle.tracker())
            else {
                return Ok(());
            };
            let count = track_next_committed(&tracker_rc)?;
            let active_rows = match count.as_constant() {
                Some(value) if count.log_size() == 0 => {
                    field_to_usize(value, "the join's output row count")?
                }
                _ => {
                    return Err(ark_piop::errors::SnarkError::VerifierError(
                        ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(
                            "the join's output row count is not a committed scalar".to_string(),
                        ),
                    ));
                }
            };
            let contig_activator = tracker_rc
                .borrow_mut()
                .get_or_build_contig_one_poly(current_table.log_size(), active_rows)?;
            let updated_table = append_activator_verifier(&current_table, contig_activator);
            let updated_table = Self::update_constraints_verifier(
                &updated_table,
                self.join_mode(),
                &left_names,
                &right_names,
            );
            virtualized_ir
                .set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
            return Ok(());
        }

        let Some(fk_input) = self.fk_side_input() else {
            return Ok(());
        };

        let fk_table = match virtualized_ir.payload_for_node(&fk_input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        let current_table = virtualized_ir
            .payload_for_node(&id)
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(table.clone()),
                _ => None,
            })
            .unwrap_or_default();

        let updated_table = Self::merge_partial_output_verifier(&current_table, &fk_table);
        let updated_table = Self::update_constraints_verifier(
            &updated_table,
            self.join_mode(),
            &left_names,
            &right_names,
        );
        debug_assert!(
            updated_table
                .tracked_oracles_iter()
                .all(|(_, oracle)| oracle.log_size() == updated_table.log_size()),
            "Join oracle output contains columns from mixed log-size domains (verifier)"
        );
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }
    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let output_table = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Join output payload missing"),
        };
        let left_table = match virtualized_ir.payload_for_node(&self.left.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Join left payload missing"),
        };
        let right_table = match virtualized_ir.payload_for_node(&self.right.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Join right payload missing"),
        };

        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(join_gadget::LEFT_LABEL.to_string(), left_table);
        gadget_payload.insert(join_gadget::RIGHT_LABEL.to_string(), right_table);
        gadget_payload.insert(join_gadget::OUTPUT_LABEL.to_string(), output_table);
        virtualized_ir.set_payload_for_node(
            self.gadget.id(),
            Some(PayloadStructure::GadgetPayload(gadget_payload)),
        );

        Ok(())
    }
}

impl<B: SnarkBackend> IsLpNode<B> for LpNode<B> {
    fn from_lp(plan: datafusion_expr::LogicalPlan, self_ref: Weak<Node<B>>) -> Self
    where
        Self: Sized,
    {
        let join = if let datafusion_expr::LogicalPlan::Join(join) = plan {
            join
        } else {
            panic!("Expected Join LogicalPlan");
        };
        // Both join protocols prove inner equijoins without a residual filter.
        assert!(
            join.join_type == datafusion_expr::JoinType::Inner
                && !join.on.is_empty()
                && join.filter.is_none(),
            "only inner equijoins without a join filter are supported, got {} join with {} keys{}",
            join.join_type,
            join.on.len(),
            if join.filter.is_some() {
                " and a filter"
            } else {
                ""
            },
        );
        // Every join starts as MANY_TO_MANY. The `PkFkSpecialization`
        // pp_optimizer rule upgrades the ones whose PK/FK metadata supports a
        // specialized protocol; without the rule they all stay MANY_TO_MANY.
        let join_mode = modes::JoinMode::MANY_TO_MANY;
        let left = Tree::<B>::from_logical_plan(&join.left).root().clone();
        let right = Tree::<B>::from_logical_plan(&join.right).root().clone();
        let join_scope_node = self_ref.clone();
        let on: JoinOnNodes<B> = join
            .on
            .iter()
            .map(|(l, r)| {
                let left_node = Tree::<B>::from_expr(
                    l,
                    Some(self_ref.clone()),
                    vec![
                        join_scope_node.clone(),
                        Arc::downgrade(&left),
                        Arc::downgrade(&right),
                    ],
                )
                .root()
                .clone();
                let right_node = Tree::<B>::from_expr(
                    r,
                    Some(self_ref.clone()),
                    vec![
                        join_scope_node.clone(),
                        Arc::downgrade(&left),
                        Arc::downgrade(&right),
                    ],
                )
                .root()
                .clone();
                (left_node, right_node)
            })
            .collect();
        let filter = join.filter.as_ref().map(|expr| {
            Tree::<B>::from_expr(expr, Some(self_ref.clone()), vec![join_scope_node.clone()])
                .root()
                .clone()
        });

        let gadget = Arc::new(Node::Gadget(Arc::new(
            crate::irs::nodes::plan::lps::join::gadget::GadgetNode::<B>::new(
                join.clone(),
                join_mode,
            ),
        )));

        LpNode {
            left,
            right,
            on,
            filter,
            gadget,
            join,
            join_mode: RwLock::new(join_mode),
            full_materialized_active_rows: Mutex::new(None),
        }
    }

    fn lp(&self) -> LogicalPlan {
        LogicalPlan::Join(self.join.clone())
    }
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
        .unwrap_or_else(|| ACTIVATOR_FIELD.clone());
    polys.insert(activator_field, activator);
    let schema = table.schema_ref().map(|schema| {
        let fields = polys
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        Schema::new_with_metadata(fields, schema.metadata().clone())
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
        .unwrap_or_else(|| ACTIVATOR_FIELD.clone());
    oracles.insert(activator_field, activator);
    let schema = table.schema_ref().map(|schema| {
        let fields = oracles
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    arithmetic::table_oracle::TrackedTableOracle::new(schema, oracles, table.log_size())
}

fn active_row_count_from_dataframe(df: &datafusion::prelude::DataFrame) -> usize {
    let batches = crate::session::block_on(df.clone().collect())
        .expect("Join output-hint collection should succeed");
    let has_activator = df
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
                .expect("Join output batch missing activator column");
            let activator = batch
                .column(activator_idx)
                .as_any()
                .downcast_ref::<datafusion::arrow::array::BooleanArray>()
                .expect("Join activator column should be boolean");
            (0..activator.len())
                .filter(|&i| activator.is_valid(i) && activator.value(i))
                .count()
        })
        .sum()
}

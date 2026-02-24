use std::sync::{Arc, Mutex, Weak};

use crate::irs::{
    nodes::{
        IsLpNode, IsNode, IsPlanNode, Node, ProverNodeOps, VerifierNodeOps,
        gadget::lps::join as join_gadget,
    },
    payloads::PayloadStructure,
    tree::Tree,
};
use arithmetic::{
    ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, ROW_ID_COL_NAME, ROW_ID_FIELD, is_system_column,
};
use ark_ff::BigInteger;
use ark_piop::SnarkBackend;
use datafusion::arrow::array::Array;
use datafusion::arrow::datatypes::Schema;
use datafusion_expr::{Join, LogicalPlan};
use indexmap::IndexMap;
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
    // Single source of truth for join optimization/materialization mode.
    join_mode: modes::JoinMode,
    // Cached from `output()` so full-materialized add_virtual_witness can rebuild
    // a contiguous activator deterministically on prover and verifier.
    full_materialized_active_rows: Mutex<Option<usize>>,
}

impl<B: SnarkBackend> LpNode<B> {
    fn join_mode(&self) -> modes::JoinMode {
        self.join_mode
    }

    fn should_fully_materialize(&self) -> bool {
        // Keep the plan-side materialization policy exactly in sync with the join
        // gadget mode:
        // - MANY_TO_MANY gadget => full materialization
        // - HasOne gadget (all other modes) => partial materialization
        self.join_mode() == modes::JoinMode::MANY_TO_MANY
    }

    fn fk_side_input(&self) -> Option<&Arc<Node<B>>> {
        match self.join_mode() {
            // ONE_TO_MANY: left is unique side, right is FK side.
            modes::JoinMode::ONE_TO_MANY => Some(&self.right),
            // MANY_TO_ONE: right is unique side, left is FK side.
            modes::JoinMode::MANY_TO_ONE => Some(&self.left),
            // ONE_TO_ONE: keep side choice deterministic and aligned with
            // `output()`/hint-side partial policy below.
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

    fn preserve_row_id_prover(
        current: &arithmetic::table::TrackedTable<B>,
        existing: Option<&arithmetic::table::TrackedTable<B>>,
    ) -> arithmetic::table::TrackedTable<B> {
        let current_has_row_id = current
            .tracked_polys()
            .keys()
            .any(|field| field.name() == ROW_ID_COL_NAME);
        if current_has_row_id {
            return current.clone();
        }
        let Some(existing) = existing else {
            return current.clone();
        };
        let existing_cols = existing.tracked_polys();
        let Some((row_field, row_poly)) = existing_cols
            .iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
            .map(|(field, poly)| (field.clone(), poly.clone()))
        else {
            return current.clone();
        };
        debug_assert_eq!(current.log_size(), existing.log_size());
        let mut tracked_polys = current.tracked_polys();
        tracked_polys.insert(row_field.clone(), row_poly);
        let schema = current
            .schema_ref()
            .map(|schema| {
                let mut fields = schema
                    .fields()
                    .iter()
                    .map(|f| f.as_ref().clone())
                    .collect::<Vec<_>>();
                if !fields.iter().any(|f| f.name() == ROW_ID_COL_NAME) {
                    fields.push(row_field.as_ref().clone());
                }
                Schema::new_with_metadata(fields, schema.metadata().clone())
            })
            .or_else(|| {
                Some(Schema::new(
                    tracked_polys
                        .keys()
                        .map(|f| f.as_ref().clone())
                        .collect::<Vec<_>>(),
                ))
            });
        arithmetic::table::TrackedTable::new(schema, tracked_polys, current.log_size())
    }

    fn preserve_row_id_verifier(
        current: &arithmetic::table_oracle::TrackedTableOracle<B>,
        existing: Option<&arithmetic::table_oracle::TrackedTableOracle<B>>,
    ) -> arithmetic::table_oracle::TrackedTableOracle<B> {
        let current_has_row_id = current
            .tracked_oracles()
            .keys()
            .any(|field| field.name() == ROW_ID_COL_NAME);
        if current_has_row_id {
            return current.clone();
        }
        let Some(existing) = existing else {
            return current.clone();
        };
        let existing_cols = existing.tracked_oracles();
        let Some((row_field, row_oracle)) = existing_cols
            .iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
            .map(|(field, oracle)| (field.clone(), oracle.clone()))
        else {
            return current.clone();
        };
        debug_assert_eq!(current.log_size(), existing.log_size());
        let mut tracked_oracles = current.tracked_oracles();
        tracked_oracles.insert(row_field.clone(), row_oracle);
        let schema = current
            .schema_ref()
            .map(|schema| {
                let mut fields = schema
                    .fields()
                    .iter()
                    .map(|f| f.as_ref().clone())
                    .collect::<Vec<_>>();
                if !fields.iter().any(|f| f.name() == ROW_ID_COL_NAME) {
                    fields.push(row_field.as_ref().clone());
                }
                Schema::new_with_metadata(fields, schema.metadata().clone())
            })
            .or_else(|| {
                Some(Schema::new(
                    tracked_oracles
                        .keys()
                        .map(|f| f.as_ref().clone())
                        .collect::<Vec<_>>(),
                ))
            });
        arithmetic::table_oracle::TrackedTableOracle::new(
            schema,
            tracked_oracles,
            current.log_size(),
        )
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
            let active_rows = self.cached_full_materialized_active_rows();
            let key = full_materialized_active_rows_misc_key(id, virtualized_ir.tree());
            tracker_rc
                .borrow_mut()
                .insert_miscellaneous_field(key, B::F::from(active_rows as u64));
            let contig_activator = tracker_rc
                .borrow_mut()
                .get_or_build_contig_one_poly(current_table.log_size(), active_rows)?;
            let updated_table = append_activator_prover(&current_table, contig_activator);
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

        let mut merged_polys = current_table.tracked_polys();

        // Copy FK-side columns exactly into the join output payload.
        for (field, poly) in fk_table.tracked_polys_iter() {
            if field.name() == ACTIVATOR_COL_NAME {
                continue;
            }
            if let Some(existing_field) = merged_polys
                .keys()
                .find(|existing| existing.name() == field.name())
                .cloned()
            {
                merged_polys.swap_remove(&existing_field);
            }
            merged_polys.insert(field.clone(), poly.clone());
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

        let updated_table = arithmetic::table::TrackedTable::new(schema, merged_polys, log_size);
        // Partial-join output must not mix row domains: every output column must
        // share the table log-size (FK-side domain).
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
        let left_table =
            Self::preserve_row_id_prover(&left_table, gadget_payload.get(join_gadget::LEFT_LABEL));
        let right_table = Self::preserve_row_id_prover(
            &right_table,
            gadget_payload.get(join_gadget::RIGHT_LABEL),
        );
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
        planned_ir: &mut crate::prover::irs::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let left_hint_df = match planned_ir.payload_for_node(&self.left.id()) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df.clone(),
            _ => return Ok(()),
        };
        let right_hint_df = match planned_ir.payload_for_node(&self.right.id()) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df.clone(),
            _ => return Ok(()),
        };
        let output_hint_df = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df.clone(),
            _ => return Ok(()),
        };

        let mut gadget_payload = match planned_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(
            join_gadget::LEFT_LABEL.to_string(),
            crate::irs::nodes::hints::HintDF::new_virtual(left_hint_df.data_frame().clone()),
        );
        gadget_payload.insert(
            join_gadget::RIGHT_LABEL.to_string(),
            crate::irs::nodes::hints::HintDF::new_virtual(right_hint_df.data_frame().clone()),
        );
        gadget_payload.insert(
            join_gadget::OUTPUT_LABEL.to_string(),
            crate::irs::nodes::hints::HintDF::new_virtual(output_hint_df.data_frame().clone()),
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
            // Partial mode (HasOne): keep FK-side row domain and only materialize PK-side
            // columns. This keeps virtual/materialized columns on the same log-size.
            hints::build_partial_output_dataframe(
                left_hint_df.data_frame().clone(),
                right_hint_df.data_frame().clone(),
                &self.join,
                self.join_mode(),
            )
        };
        if full_materialization {
            self.cache_full_materialized_active_rows(active_row_count_from_dataframe(&joined));
        }

        let left_fields = left_hint_df
            .data_frame()
            .schema()
            .fields()
            .iter()
            .map(|field| field.name().clone())
            .collect::<std::collections::HashSet<_>>();
        let right_fields = right_hint_df
            .data_frame()
            .schema()
            .fields()
            .iter()
            .map(|field| field.name().clone())
            .collect::<std::collections::HashSet<_>>();

        let should_materialize: IndexMap<_, _> = joined
            .schema()
            .fields()
            .iter()
            .map(|field| {
                let name = field.name();
                let mat = if name == ROW_ID_COL_NAME
                    || (full_materialization && name == ACTIVATOR_COL_NAME)
                {
                    false
                } else if full_materialization {
                    true
                } else {
                    // Partial path (HasOne): materialize only one side's data and
                    // keep the preserved-side columns virtual.
                    match self.join_mode() {
                        modes::JoinMode::ONE_TO_MANY => left_fields.contains(name),
                        modes::JoinMode::MANY_TO_ONE => right_fields.contains(name),
                        // ONE_TO_ONE: keep right as FK-preserved side (virtual), and
                        // materialize only the opposite side.
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
    fn output(&self) -> crate::irs::nodes::verifier_hint::VerifierHint {
        let left_hint = match self.left.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Join left input cannot be a gadget node"),
        };
        let right_hint = match self.right.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Join right input cannot be a gadget node"),
        };

        let full_materialization = self.should_fully_materialize();

        // Build output schema from child schemas only (metadata path, no DataFrame eval).
        let mut output_fields: indexmap::IndexMap<String, datafusion::arrow::datatypes::FieldRef> =
            indexmap::IndexMap::new();
        for field in left_hint.schema().fields() {
            if !is_system_column(field.name()) {
                output_fields.insert(field.name().to_string(), field.clone());
            }
        }
        for field in right_hint.schema().fields() {
            if !is_system_column(field.name()) {
                output_fields
                    .entry(field.name().to_string())
                    .or_insert_with(|| field.clone());
            }
        }
        output_fields.insert(ACTIVATOR_COL_NAME.to_string(), ACTIVATOR_FIELD.clone());
        output_fields.insert(ROW_ID_COL_NAME.to_string(), ROW_ID_FIELD.clone());

        let left_fields = left_hint
            .schema()
            .fields()
            .iter()
            .filter(|field| !is_system_column(field.name()))
            .map(|field| field.name().to_string())
            .collect::<std::collections::HashSet<_>>();
        let right_fields = right_hint
            .schema()
            .fields()
            .iter()
            .filter(|field| !is_system_column(field.name()))
            .map(|field| field.name().to_string())
            .collect::<std::collections::HashSet<_>>();

        let field_materialization = output_fields
            .values()
            .map(|field| {
                let name = field.name();
                let mat = if name == ROW_ID_COL_NAME || (full_materialization && name == ACTIVATOR_COL_NAME) {
                    false
                } else if full_materialization {
                    true
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
            .collect::<indexmap::IndexMap<_, _>>();

        let schema = std::sync::Arc::new(datafusion::arrow::datatypes::Schema::new_with_metadata(
            output_fields
                .values()
                .map(|field| field.as_ref().clone())
                .collect::<Vec<_>>(),
            left_hint.schema().metadata().clone(),
        ));

        let input_log_size = match self.fk_side_input() {
            Some(input_node) => match input_node.as_ref() {
                Node::Plan(plan_node) => {
                    <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                        plan_node,
                    )
                    .log_size()
                }
                Node::Gadget(_) => 0,
            },
            None => left_hint.log_size(),
        };

        crate::irs::nodes::verifier_hint::VerifierHint::from_field_materialization(schema, field_materialization, input_log_size)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for LpNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::verifier::irs::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let _ = (id, planned_ir);
        Ok(())
    }
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
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
            let key = full_materialized_active_rows_misc_key(id, virtualized_ir.tree());
            let active_rows_field = tracker_rc.borrow().miscellaneous_field_element(&key)?;
            let active_rows = field_to_usize::<B::F>(active_rows_field)?;
            let contig_activator = tracker_rc
                .borrow_mut()
                .get_or_build_contig_one_oracle(current_table.log_size(), active_rows)?;
            let updated_table = append_activator_verifier(&current_table, contig_activator);
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

        let mut merged_oracles = current_table.tracked_oracles();

        // Copy FK-side columns exactly into the join output payload.
        for (field, oracle) in fk_table.tracked_oracles_iter() {
            if field.name() == ACTIVATOR_COL_NAME {
                continue;
            }
            if let Some(existing_field) = merged_oracles
                .keys()
                .find(|existing| existing.name() == field.name())
                .cloned()
            {
                merged_oracles.swap_remove(&existing_field);
            }
            merged_oracles.insert(field.clone(), oracle.clone());
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

        let updated_table =
            arithmetic::table_oracle::TrackedTableOracle::new(schema, merged_oracles, log_size);
        // Verifier-side mirror of prover invariant: all output oracles must be on
        // the same row domain.
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
        let left_table = Self::preserve_row_id_verifier(
            &left_table,
            gadget_payload.get(join_gadget::LEFT_LABEL),
        );
        let right_table = Self::preserve_row_id_verifier(
            &right_table,
            gadget_payload.get(join_gadget::RIGHT_LABEL),
        );
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
        // Decide mode at LP ingestion time so both plan and gadget are always synchronized.
        let join_mode = modes::decide_join_mode(&join);
        let left = Tree::<B>::from_logical_plan(&join.left).root().clone();
        let right = Tree::<B>::from_logical_plan(&join.right).root().clone();
        let join_scope_node = self_ref.clone();
        let on: Vec<(Arc<Node<B>>, Arc<Node<B>>)> = join
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
            crate::irs::nodes::gadget::lps::join::GadgetNode::<B>::new(join.clone(), join_mode),
        )));

        LpNode {
            left,
            right,
            on,
            filter,
            gadget,
            join,
            join_mode,
            full_materialized_active_rows: Mutex::new(None),
        }
    }

    fn lp(&self) -> LogicalPlan {
        LogicalPlan::Join(self.join.clone())
    }
}

const JOIN_FULL_MATERIALIZED_ACTIVE_ROWS_PREFIX: &str = "join_full_materialized_active_rows";

fn full_materialized_active_rows_misc_key<B: SnarkBackend>(
    target_id: crate::irs::nodes::NodeId,
    tree: &Tree<B>,
) -> String {
    fn dfs_rank<B: SnarkBackend>(
        node: &Arc<Node<B>>,
        target_id: crate::irs::nodes::NodeId,
        rank: &mut usize,
        found: &mut Option<usize>,
    ) {
        if found.is_some() {
            return;
        }
        let is_join_plan = matches!(node.as_ref(), Node::Plan(_)) && node.name() == "Join";
        if is_join_plan {
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
    let join_rank = found.unwrap_or_else(|| {
        panic!(
            "Join node id {:?} was not found while computing misc key",
            target_id
        )
    });
    format!("{JOIN_FULL_MATERIALIZED_ACTIVE_ROWS_PREFIX}_{join_rank}")
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
    let batches = collect_blocking(df.clone()).expect("Join output-hint collection should succeed");
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
                        "join contig n does not fit into usize".to_string(),
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

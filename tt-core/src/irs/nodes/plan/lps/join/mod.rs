use std::sync::{Arc, Weak};

use crate::irs::{
    nodes::{
        IsLpNode, IsNode, IsPlanNode, Node, ProverNodeOps, VerifierNodeOps,
        gadget::lps::join as join_gadget,
    },
    payloads::PayloadStructure,
    tree::Tree,
};
use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use ark_piop::SnarkBackend;
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

    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
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
        // Full-materialized joins already contain all output columns.
        if self.should_fully_materialize() {
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

impl<B: SnarkBackend> IsPlanNode<B> for LpNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        Some(self.gadget.as_ref().clone())
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let left_hint_df = match self.left.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("Join left input cannot be a gadget node"),
        };
        let right_hint_df = match self.right.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
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
                let mat = if name == ROW_ID_COL_NAME {
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

impl<B: SnarkBackend> VerifierNodeOps<B> for LpNode<B> {
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Full-materialized joins already contain all output columns.
        if self.should_fully_materialize() {
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
        }
    }

    fn lp(&self) -> LogicalPlan {
        LogicalPlan::Join(self.join.clone())
    }
}

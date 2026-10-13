use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{Field, FieldRef, Schema};
use datafusion_expr::{Filter, LogicalPlan};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{
            IsLpNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
            hints::HintDF,
        },
        payloads::PayloadStructure,
        tree::Tree,
    },
    prover::irs::VirtualizedIr as ProverVirtualizedIr,
    verifier::irs::VirtualizedIr as VerifierVirtualizedIr,
};

pub mod gadget;
mod hints;

pub struct LpNode<B>
where
    B: SnarkBackend,
{
    filter: Filter,
    input: Arc<Node<B>>,
    predicate: Arc<Node<B>>,
    gadget: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for LpNode<B> {
    fn name(&self) -> String {
        "Filter".to_string()
    }

    fn display(&self) -> String {
        format!(
            "Filter\nInput: {}, predicate: {}",
            self.input.name(),
            self.filter.predicate
        )
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.input.clone(), self.predicate.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for LpNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table,
            _ => return Ok(()),
        };

        let predicate_table = match virtualized_ir.payload_for_node(&self.predicate.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table,
            _ => return Ok(()),
        };

        let mut merged_polys = input_table.tracked_polys();

        // The output activator is the predicate column itself; the gadget
        // checks that it equals input_activator * predicate.
        let predicate_data_indices = predicate_table.data_tracked_polys_indices();
        let predicate_data_idx = *predicate_data_indices
            .first()
            .expect("Filter predicate output should include a data column");
        let predicate_col = predicate_table.tracked_col_by_ind(predicate_data_idx);
        let predicate_poly = predicate_col.data_tracked_poly();
        let output_activator = predicate_poly.clone();
        merged_polys.insert(ACTIVATOR_FIELD.clone(), output_activator);

        let metadata = input_table
            .schema_ref()
            .map(|s| s.metadata().clone())
            .unwrap_or_default();

        let fields = merged_polys
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        let schema = Some(Schema::new_with_metadata(fields, metadata));

        let log_size = input_table.log_size();

        // Side (char-domain) segments pass through by reference so string
        // gadgets above this filter (LIKE, pre-filter) can still bind to them.
        // The side activator is untouched: consumers narrow it against the row
        // activator themselves.
        let side_cols = input_table.side_cols();
        let updated_table = TrackedTable::new_with_side_cols(
            schema.clone(),
            merged_polys.clone(),
            log_size,
            side_cols,
        );
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }

    /// The gadget takes the input activator, the output activator and the
    /// binary predicate column, and proves that the output activator is
    /// computed correctly from the other two.
    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let activator_only = |table: &TrackedTable<B>, col_name: &str| {
            let idx = table
                .tracked_polys()
                .keys()
                .position(|field| field.name() == ACTIVATOR_COL_NAME)
                .expect("table should include activator column");
            let mut output = table.tracked_subtable_by_indices(&[idx]);
            output.rename_col(0, col_name);
            output
        };

        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => Some(table.clone()),
            _ => None,
        };
        let output_table =
            virtualized_ir
                .payload_for_node(&_id)
                .and_then(|payload| match payload {
                    PayloadStructure::PlanPayload(table) => Some(table.clone()),
                    _ => None,
                });
        let predicate_table = virtualized_ir
            .payload_for_node(&self.predicate.id())
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(table.clone()),
                _ => None,
            });
        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        if let Some(input) = input_table.as_ref() {
            gadget_payload.insert(
                gadget::INPUT_ACTIVATOR_LABEL.to_string(),
                activator_only(input, "input_activator"),
            );
        }
        if let Some(output) = output_table.as_ref() {
            gadget_payload.insert(
                gadget::OUTPUT_ACTIVATOR_LABEL.to_string(),
                activator_only(output, "output_activator"),
            );
        }
        if let Some(pred_table) = predicate_table {
            gadget_payload.insert(gadget::FILTER_PREDICATE_LABEL.to_string(), pred_table);
        }
        if !gadget_payload.is_empty() {
            virtualized_ir.set_payload_for_node(
                self.gadget.id(),
                Some(PayloadStructure::GadgetPayload(gadget_payload)),
            );
        }
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for LpNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table,
            _ => return Ok(()),
        };

        let predicate_table = match virtualized_ir.payload_for_node(&self.predicate.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table,
            _ => return Ok(()),
        };

        let mut merged_polys = input_table.tracked_oracles();

        let predicate_data_indices = predicate_table.data_tracked_oracles_indices();
        let predicate_data_idx = *predicate_data_indices
            .first()
            .expect("Filter predicate output should include a data column");
        let predicate_oracle = predicate_table
            .tracked_col_oracle_by_ind(predicate_data_idx)
            .data_tracked_oracle();
        let output_activator = predicate_oracle.clone();
        merged_polys.insert(ACTIVATOR_FIELD.clone(), output_activator);

        let metadata = input_table
            .schema_ref()
            .map(|s| s.metadata().clone())
            .unwrap_or_default();

        let fields = merged_polys
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        let schema = Some(Schema::new_with_metadata(fields, metadata));

        let log_size = input_table.log_size();

        let side_cols = input_table.side_cols();
        let updated_table =
            TrackedTableOracle::new_with_side_cols(schema, merged_polys, log_size, side_cols);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }
    fn initialize_gadgets(
        &self,
        id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let activator_only = |table: &TrackedTableOracle<B>, col_name: &str| {
            let (field_ref, activator_oracle) = table
                .tracked_oracles_iter()
                .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
                .expect("table should include activator column");
            let renamed_field = Arc::new(Field::new(
                col_name,
                field_ref.data_type().clone(),
                field_ref.is_nullable(),
            ));
            let mut oracles = IndexMap::new();
            oracles.insert(renamed_field.clone(), activator_oracle.clone());
            let schema = table.schema_ref().map(|schema| {
                Schema::new_with_metadata(
                    vec![renamed_field.as_ref().clone()],
                    schema.metadata().clone(),
                )
            });
            TrackedTableOracle::new(schema, oracles, table.log_size())
        };

        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => Some(table),
            _ => None,
        };
        let output_table = virtualized_ir
            .payload_for_node(&id)
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(table),
                _ => None,
            });
        let predicate_table = virtualized_ir
            .payload_for_node(&self.predicate.id())
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(table),
                _ => None,
            });

        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };

        if let Some(input) = input_table.as_ref() {
            gadget_payload.insert(
                gadget::INPUT_ACTIVATOR_LABEL.to_string(),
                activator_only(input, "input_activator"),
            );
        }
        if let Some(output) = output_table.as_ref() {
            gadget_payload.insert(
                gadget::OUTPUT_ACTIVATOR_LABEL.to_string(),
                activator_only(output, "output_activator"),
            );
        }
        if let Some(pred_table) = predicate_table {
            gadget_payload.insert(
                gadget::FILTER_PREDICATE_LABEL.to_string(),
                pred_table.clone(),
            );
        }

        if !gadget_payload.is_empty() {
            virtualized_ir.set_payload_for_node(
                self.gadget.id(),
                Some(PayloadStructure::GadgetPayload(gadget_payload)),
            );
        }
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for LpNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        Some(self.gadget.as_ref().clone())
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsProverPlanNode<B> for LpNode<B> {
    fn output(&self) -> HintDF {
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsProverPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Filter input cannot be a gadget node"),
        };

        let output_df = hints::build_output_dataframe(input_hint_df.data_frame(), &self.filter);
        let output_df = crate::irs::nodes::hints::sort_by_row_id_if_present(output_df)
            .expect("filter output sort should succeed");

        // Keep all output columns virtual; the activator is filled in by wiring.
        let should_materialize: IndexMap<FieldRef, bool> = output_df
            .schema()
            .fields()
            .iter()
            .map(|field| (field.clone(), false))
            .collect();

        crate::irs::nodes::hints::HintDF::new(output_df, should_materialize)
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for LpNode<B> {
    fn output(&self) -> HintDF {
        // Verifier planning only needs schema. Filter preserves schema.
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Filter input cannot be a gadget node"),
        };
        input_hint_df.as_virtual_view()
    }
}

impl<B: SnarkBackend> IsLpNode<B> for LpNode<B> {
    fn from_lp(_plan: LogicalPlan, self_ref: std::sync::Weak<Node<B>>) -> Self
    where
        Self: Sized,
    {
        let filter = match _plan {
            LogicalPlan::Filter(filter) => filter,
            _ => panic!("Expected LogicalPlan::Filter"),
        };

        let input = Tree::<B>::from_logical_plan(&filter.input).root().clone();

        let predicate = Tree::<B>::from_expr(
            &filter.predicate,
            Some(self_ref),
            vec![Arc::downgrade(&input)],
        )
        .root()
        .clone();

        let gadget = Arc::new(Node::<B>::Gadget(Arc::new(gadget::FilterNode::new())));

        Self {
            filter,
            input,
            predicate,
            gadget,
        }
    }

    fn lp(&self) -> LogicalPlan {
        LogicalPlan::Filter(self.filter.clone())
    }
}

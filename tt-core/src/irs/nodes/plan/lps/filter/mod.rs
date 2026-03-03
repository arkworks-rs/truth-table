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
            gadget::lps::filter::{
                self, FILTER_PREDICATE_LABEL, INPUT_ACTIVATOR_LABEL, OUTPUT_ACTIVATOR_LABEL,
            },
            hints::HintDF,
        },
        payloads::PayloadStructure,
        tree::Tree,
    },
    prover::irs::VirtualizedIr as ProverVirtualizedIr,
    verifier::irs::VirtualizedIr as VerifierVirtualizedIr,
};

mod hints;

/// The implementation of a filter node in the prover proof tree.
pub struct LpNode<B>
where
    B: SnarkBackend,
{
    // The filter information from DataFusion
    filter: Filter,
    // The prover plan children nodes for the Filter expressions
    input: Arc<Node<B>>,
    // The prover predicate expression node for the filter condition
    predicate: Arc<Node<B>>,
    // The gadget node for proving the filter operation
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
        // Pull the tracked table that is the input to this filter node.
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        // Pull the predicate output table.
        let predicate_table = match virtualized_ir.payload_for_node(&self.predicate.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        let mut merged_polys = input_table.tracked_polys();

        // Replace the activator column with input_activator AND predicate output.
        let predicate_data_indices = predicate_table.data_tracked_polys_indices();
        let predicate_data_idx = *predicate_data_indices
            .first()
            .expect("Filter predicate output should include a data column");
        let predicate_col = predicate_table.tracked_col_by_ind(predicate_data_idx);
        let predicate_poly = predicate_col.data_tracked_poly();
        // let output_activator = match input_table.activator_tracked_poly() {
        //     Some(input_activator) => &predicate_poly * &input_activator,
        //     None => predicate_poly,
        // };
        let output_activator = predicate_poly.clone();
        merged_polys.insert(ACTIVATOR_FIELD.clone(), output_activator);

        // Prefer existing schema metadata, otherwise inherit from the input table.
        let metadata = input_table
            .schema_ref()
            .map(|s| s.metadata().clone())
            .unwrap_or_default();

        // Get the fields from the merged polys for the new schema.
        let fields = merged_polys
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        // Create the new schema with the merged fields and metadata.
        let schema = Some(Schema::new_with_metadata(fields, metadata));

        // Keep the existing log size when set; otherwise inherit from the input.
        let log_size = input_table.log_size();

        let updated_table = TrackedTable::new(schema.clone(), merged_polys.clone(), log_size);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }

    /// The gadget for the filter node only takes in 1. the input activator column, 2. the output activator column and 3. the binary output of the predicate column.
    /// Then the gadget proves to you that the output activator column is correctly computed from the input activator column and the predicate column.
    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Helper to extract a table containing only the activator column.
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

        // Fetch the input table to this filter node.
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => Some(table.clone()),
            _ => None,
        };
        // Fetch the output table of this filter node.
        let output_table =
            virtualized_ir
                .payload_for_node(&_id)
                .and_then(|payload| match payload {
                    PayloadStructure::PlanPayload(table) => Some(table.clone()),
                    _ => None,
                });
        // Fetch the predicate table for this filter node.
        let predicate_table = virtualized_ir
            .payload_for_node(&self.predicate.id())
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(table.clone()),
                _ => None,
            });
        // Get a mutable reference to the gadget payload for this filter node.
        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        // Now we start adding the necessary tables to the gadget payload.
        // 1. Input activator table, we rename the activator column to "input_activator"
        if let Some(input) = input_table.as_ref() {
            gadget_payload.insert(
                INPUT_ACTIVATOR_LABEL.to_string(),
                activator_only(input, "input_activator"),
            );
        }
        // 2. Output activator table, we rename the activator column to "output_activator"
        if let Some(output) = output_table.as_ref() {
            gadget_payload.insert(
                OUTPUT_ACTIVATOR_LABEL.to_string(),
                activator_only(output, "output_activator"),
            );
        }
        // 3. Predicate table, as is.
        if let Some(pred_table) = predicate_table {
            gadget_payload.insert(FILTER_PREDICATE_LABEL.to_string(), pred_table);
        }
        // Adding the gadget payload to the virtualized IR if not empty.
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
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
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
        // Pull the tracked table from the filter's input.
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        // Pull the predicate output table.
        let predicate_table = match virtualized_ir.payload_for_node(&self.predicate.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        let mut merged_polys = input_table.tracked_oracles();

        // Replace the activator column with input_activator AND predicate output.
        let predicate_data_indices = predicate_table.data_tracked_oracles_indices();
        let predicate_data_idx = *predicate_data_indices
            .first()
            .expect("Filter predicate output should include a data column");
        let binding = predicate_table.tracked_oracles();
        let (_field, predicate_oracle) = binding
            .get_index(predicate_data_idx)
            .expect("predicate data index out of bounds");
        // let output_activator = match input_table.activator_tracked_poly() {
        //     Some(input_activator) => predicate_oracle * &input_activator,
        //     None => predicate_oracle.clone(),
        // };
        let output_activator = predicate_oracle.clone();
        merged_polys.insert(ACTIVATOR_FIELD.clone(), output_activator);

        // Prefer existing schema metadata, otherwise inherit from the input table.
        let metadata = input_table
            .schema_ref()
            .map(|s| s.metadata().clone())
            .unwrap_or_default();

        let fields = merged_polys
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        let schema = Some(Schema::new_with_metadata(fields, metadata));

        // Keep the existing log size when set; otherwise inherit from the input.
        let log_size = input_table.log_size();

        let updated_table = TrackedTableOracle::new(schema, merged_polys, log_size);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }
    fn initialize_gadgets(
        &self,
        id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Helper to extract a table containing only the activator column.
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
            Some(PayloadStructure::PlanPayload(table)) => Some(table.clone()),
            _ => None,
        };
        let output_table = virtualized_ir
            .payload_for_node(&id)
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
                INPUT_ACTIVATOR_LABEL.to_string(),
                activator_only(input, "input_activator"),
            );
        }
        if let Some(output) = output_table.as_ref() {
            gadget_payload.insert(
                OUTPUT_ACTIVATOR_LABEL.to_string(),
                activator_only(output, "output_activator"),
            );
        }
        if let Some(pred_table) = predicate_table {
            gadget_payload.insert(FILTER_PREDICATE_LABEL.to_string(), pred_table);
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
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
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
        // Derive the output by updating the activator column instead of dropping rows.
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
        // Verifier must not collect DataFrames. Use the no-collection variant.
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Filter input cannot be a gadget node"),
        };

        let output_df =
            hints::build_output_dataframe_for_verifier(input_hint_df.data_frame(), &self.filter);

        let should_materialize: IndexMap<FieldRef, bool> = output_df
            .schema()
            .fields()
            .iter()
            .map(|field| (field.clone(), false))
            .collect();

        crate::irs::nodes::hints::HintDF::new(output_df, should_materialize)
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

        // Recurse into the input subtree and fetch the logical plan that feeds this
        // filter.
        let input = Tree::<B>::from_logical_plan(&filter.input).root().clone();

        // Recurse into the input subtree and fetch the expr that feeds this
        // filter.
        let predicate = Tree::<B>::from_expr(
            &filter.predicate,
            Some(self_ref),
            vec![Arc::downgrade(&input)],
        )
        .root()
        .clone();

        let gadget = Arc::new(Node::<B>::Gadget(Arc::new(filter::FilterNode::new())));

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

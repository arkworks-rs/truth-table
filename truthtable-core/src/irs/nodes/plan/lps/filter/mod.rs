use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, table::TrackedTable};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{FieldRef, Schema};
use datafusion_expr::{Filter, LogicalPlan};
use indexmap::IndexMap;

use crate::irs::{
    nodes::{
        IsGadgetNode, IsLpNode, IsNode, IsPlanNode, Node,
        gadget::{self, lps::filter},
    },
    tree::Tree,
};

mod hints;

/// The implementation of a filter node in the prover proof tree.
pub struct ProverNode<B>
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

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "Filter".to_string()
    }

    fn cost(
        &self,
        statistics: datafusion_common::Statistics,
        schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![
            self.input.clone(),
            self.predicate.clone(),
            self.gadget.clone(),
        ]
    }

    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        use crate::prover::payloads::PayloadStructure;

        // Pull the tracked table from the filter's input.
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        // Start from this node's current payload (should already include the activator).
        let current_table = virtualized_ir
            .payload_for_node(&id)
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(table.clone()),
                _ => None,
            })
            .unwrap_or_default();

        let mut merged_polys = current_table.tracked_polys();
        debug_assert!(
            !merged_polys.is_empty(),
            "Filter payload should already contain the activator column"
        );

        // Append all non-activator columns from the input into this table.
        for (field, poly) in input_table.tracked_polys_iter() {
            if field.name() == ACTIVATOR_COL_NAME {
                continue;
            }
            merged_polys
                .entry(field.clone())
                .or_insert_with(|| poly.clone());
        }

        // Prefer existing schema metadata, otherwise inherit from the input table.
        let metadata = current_table
            .schema_ref()
            .map(|s| s.metadata().clone())
            .or_else(|| input_table.schema_ref().map(|s| s.metadata().clone()))
            .unwrap_or_default();

        let fields = merged_polys
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        let schema = Some(Schema::new_with_metadata(fields, metadata));

        // Keep the existing log size when set; otherwise inherit from the input.
        let log_size = match (current_table.log_size(), input_table.log_size()) {
            (0, other) => other,
            (current, 0) => current,
            (current, input) => {
                debug_assert_eq!(current, input, "Filter log sizes should match input");
                current
            }
        };

        let updated_table = TrackedTable::new(schema, merged_polys, log_size);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ProverNode<B> {
    fn gadget(&self) -> Arc<Node<B>> {
        self.gadget.clone()
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        // Derive the output by updating the activator column instead of dropping rows.
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("Filter input cannot be a gadget node"),
        };

        let output_df = hints::build_output_dataframe(input_hint_df.data_frame(), &self.filter);

        // Only materialize the activator column; keep all other columns virtual.
        let should_materialize: IndexMap<FieldRef, bool> = output_df
            .schema()
            .fields()
            .iter()
            .map(|field| {
                (
                    field.clone(),
                    field.name() == arithmetic::ACTIVATOR_COL_NAME,
                )
            })
            .collect();

        crate::irs::nodes::hints::HintDF::new(output_df, should_materialize)
    }
}

impl<B: SnarkBackend> IsLpNode<B> for ProverNode<B> {
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
        let predicate = Tree::<B>::from_expr(&filter.predicate, Some(self_ref), input.clone())
            .root()
            .clone();

        let gadget = Arc::new(Node::<B>::Gadget(Arc::new(filter::ProverNode::new())));

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

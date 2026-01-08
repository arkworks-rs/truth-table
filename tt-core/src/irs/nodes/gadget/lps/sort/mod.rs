use std::{any::TypeId, sync::Arc};

use arithmetic::{ACTIVATOR_COL_NAME, is_system_column};
use ark_piop::SnarkBackend;
use datafusion_expr::{LogicalPlan, Sort, col, expr::Sort as SortExpr, lit};

use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};
#[cfg(test)]
mod tests;
pub const INPUT_LABEL: &str = "__input__";
pub const OUTPUT_LABEL: &str = "__output__";
pub const INPUT_SORT_EXPRS: &str = "__input_sort_exprs__";
pub const OUTPUT_SORT_EXPRS: &str = "__output_sort_exprs__";
pub struct GadgetNode<B: SnarkBackend> {
    sort: Arc<Node<B>>,
}

fn populate_output_expr(
    gadget_payload: &mut IndexMap<String, crate::irs::nodes::hints::HintDF>,
    input_hint: &crate::irs::nodes::hints::HintDF,
) -> crate::irs::nodes::hints::HintDF {
    let input_df = input_hint.data_frame().clone();
    let has_activator = input_df
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ACTIVATOR_COL_NAME);
    let sort_input_df = if has_activator {
        input_df.clone()
    } else {
        // Ensure the output carries an activator even if the input did not.
        input_df
            .clone()
            .with_column(ACTIVATOR_COL_NAME, lit(true))
            .expect("sort exprs should accept synthetic activator")
    };

    // Sort by activator first (actives first), then by the sort-expr columns.
    let mut sort_exprs: Vec<SortExpr> =
        Vec::with_capacity(1 + sort_input_df.schema().fields().len());
    sort_exprs.push(col(ACTIVATOR_COL_NAME).sort(false, false));
    sort_exprs.extend(
        sort_input_df
            .schema()
            .fields()
            .iter()
            .filter(|field| !is_system_column(field.name()))
            .map(|field| col(field.name()).sort(true, true)),
    );

    let sort = Sort {
        expr: sort_exprs,
        input: Arc::new(LogicalPlan::from(sort_input_df.logical_plan().clone())),
        fetch: None,
    };

    let sorted_df = crate::irs::nodes::plan::lps::sort::output::sort_df(&sort_input_df, &sort);
    // Project the data columns and activator (and row_id if present) into the output.
    let projected = sorted_df
        .schema()
        .fields()
        .iter()
        .filter(|field| {
            field.name() == ACTIVATOR_COL_NAME
                || field.name() == arithmetic::ROW_ID_COL_NAME
                || !is_system_column(field.name())
        })
        .map(|field| col(field.name()))
        .collect();
    let sorted_df = sorted_df
        .select(projected)
        .expect("sort exprs projection should succeed");

    let output_hint = crate::irs::nodes::hints::HintDF::new_materialized(sorted_df);
    gadget_payload.insert(OUTPUT_SORT_EXPRS.to_string(), output_hint.clone());
    output_hint
}

fn populate_sort_gadget_table<B: SnarkBackend>(
    planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    output_sort_exprs: &crate::irs::nodes::hints::HintDF,
) {
    let target_type = TypeId::of::<crate::irs::nodes::gadget::utils::sort::GadgetNode<B>>();
    let gadget_ids: Vec<_> = planned_ir
        .tree()
        .arena()
        .iter()
        .filter_map(|(node_id, node)| {
            let Node::Gadget(gadget) = node.as_ref() else {
                return None;
            };
            (gadget.as_ref().type_id() == target_type).then_some(*node_id)
        })
        .collect();

    for node_id in gadget_ids {
        let mut payload = match planned_ir.payload_for_node(&node_id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        payload.insert(
            crate::irs::nodes::gadget::utils::sort::TABLE_LABEL.to_string(),
            output_sort_exprs.clone(),
        );
        planned_ir.set_payload_for_node(node_id, Some(PayloadStructure::GadgetPayload(payload)));
    }
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Order By".to_string()
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
        let mut gadget_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        let input_hint = match gadget_payload.get(INPUT_SORT_EXPRS) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };

        let output_hint = populate_output_expr(&mut gadget_payload, &input_hint);
        populate_sort_gadget_table(planned_ir, &output_hint);
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));
        Ok(())
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.sort.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
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
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
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
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        todo!()
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn verify(
        &self,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> Default for GadgetNode<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new() -> Self {
        let sort = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::sort::GadgetNode::new(),
        )));
        Self { sort }
    }
}

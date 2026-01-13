use std::{any::TypeId, sync::Arc};

use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME, is_system_column};
use ark_piop::{SnarkBackend, arithmetic::mat_poly::mle::MLE};
use datafusion_expr::{LogicalPlan, Sort, col, expr::Sort as SortExpr, lit};

use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::gadget::utils::remat,
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
    sort_gadget: Arc<Node<B>>,
    remat_gadget: Arc<Node<B>>,
    sort_specs: Vec<(bool, bool)>,
}

fn populate_output_expr(
    gadget_payload: &mut IndexMap<String, crate::irs::nodes::hints::HintDF>,
    input_hint: &crate::irs::nodes::hints::HintDF,
    sort_specs: &[(bool, bool)],
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
    let data_fields: Vec<_> = sort_input_df
        .schema()
        .fields()
        .iter()
        .filter(|field| !is_system_column(field.name()))
        .collect();
    if data_fields.len() == sort_specs.len() {
        sort_exprs.extend(
            data_fields
                .iter()
                .zip(sort_specs.iter())
                .map(|(field, (asc, nulls_first))| col(field.name()).sort(*asc, *nulls_first)),
        );
    } else {
        sort_exprs.extend(
            data_fields
                .iter()
                .map(|field| col(field.name()).sort(true, true)),
        );
    }

    let sort = Sort {
        expr: sort_exprs,
        input: Arc::new(sort_input_df.logical_plan().clone()),
        fetch: None,
    };

    let sorted_df = crate::irs::nodes::plan::lps::sort::output::sort_df(&sort_input_df, &sort);
    // Project the data columns and activator (and row_id for deterministic ordering).
    let projected = sorted_df
        .schema()
        .fields()
        .iter()
        .filter(|field| {
            field.name() == ACTIVATOR_COL_NAME
                || field.name() == ROW_ID_COL_NAME
                || !is_system_column(field.name())
        })
        .map(|field| col(field.name()))
        .collect();
    let sorted_df = sorted_df
        .select(projected)
        .expect("sort exprs projection should succeed");

    let output_hint = crate::irs::nodes::hints::HintDF::new_materialized(sorted_df);
    // Strip row-id before storing to avoid turning it into a witness payload.
    let sanitized_output = crate::irs::nodes::hints::strip_row_id_from_hint(&output_hint);
    gadget_payload.insert(OUTPUT_SORT_EXPRS.to_string(), sanitized_output);
    output_hint
}

fn populate_sort_gadget_table<B: SnarkBackend>(
    planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    output_sort_exprs: &crate::irs::nodes::hints::HintDF,
) {
    let target_type = TypeId::of::<crate::irs::nodes::gadget::utils::contig_sort::GadgetNode<B>>();
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
            crate::irs::nodes::gadget::utils::contig_sort::TABLE_LABEL.to_string(),
            output_sort_exprs.clone(),
        );
        planned_ir.set_payload_for_node(node_id, Some(PayloadStructure::GadgetPayload(payload)));
    }
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Order By".to_string()
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

        let output_hint = populate_output_expr(&mut gadget_payload, &input_hint, &self.sort_specs);
        // Drop row-id from the input sort-exprs payload after it's been used for ordering.
        let sanitized_input = crate::irs::nodes::hints::strip_row_id_from_hint(&input_hint);
        gadget_payload.insert(INPUT_SORT_EXPRS.to_string(), sanitized_input);
        populate_sort_gadget_table(planned_ir, &output_hint);
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));
        Ok(())
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.sort_gadget.clone()]
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
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };

        let mut remat_payload = match virtualized_ir.payload_for_node(&self.remat_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        if let Some(input) = payload.get(INPUT_LABEL).cloned() {
            remat_payload.insert(remat::INPUT_LABEL.to_string(), input);
        }
        if let Some(output) = payload.get(OUTPUT_LABEL).cloned() {
            remat_payload.insert(remat::OUTPUT_LABEL.to_string(), output);
        }
        if !remat_payload.is_empty() {
            virtualized_ir.set_payload_for_node(
                self.remat_gadget.id(),
                Some(PayloadStructure::GadgetPayload(remat_payload)),
            );
        }
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
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };

        let mut remat_payload = match virtualized_ir.payload_for_node(&self.remat_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        if let Some(input) = payload.get(INPUT_LABEL).cloned() {
            remat_payload.insert(remat::INPUT_LABEL.to_string(), input);
        }
        if let Some(output) = payload.get(OUTPUT_LABEL).cloned() {
            remat_payload.insert(remat::OUTPUT_LABEL.to_string(), output);
        }
        if !remat_payload.is_empty() {
            virtualized_ir.set_payload_for_node(
                self.remat_gadget.id(),
                Some(PayloadStructure::GadgetPayload(remat_payload)),
            );
        }
        Ok(())
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

    fn honest_prover_check(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
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

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(sort: Sort) -> Self {
        let sort_specs: Vec<(bool, bool)> = sort
            .expr
            .iter()
            .map(|expr| (expr.asc, expr.nulls_first))
            .collect();
        // DataFusion sort expressions do not encode strictness, so default to true.
        let strict: bool = false;
        let sort_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::contig_sort::GadgetNode::new(
                sort_specs.clone(),
                strict,
            ),
        )));
        let remat_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::remat::GadgetNode::new(),
        )));
        Self {
            sort_gadget,
            remat_gadget,
            sort_specs,
        }
    }
}

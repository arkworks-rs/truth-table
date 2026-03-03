use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME, is_system_column};
use ark_piop::SnarkBackend;
use datafusion_expr::{Sort, col, expr::Sort as SortExpr, lit};

use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps, gadget::utils::remat},
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
    sort_specs: Vec<(String, bool, bool)>,
}

fn populate_output_expr(
    gadget_payload: &mut IndexMap<String, crate::irs::nodes::hints::HintDF>,
    input_hint: &crate::irs::nodes::hints::HintDF,
    sort_specs: &[(String, bool, bool)],
    skip_collection: bool,
) -> crate::irs::nodes::hints::HintDF {
    let input_df = input_hint.data_frame().clone();
    let has_activator = input_df
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ACTIVATOR_COL_NAME);
    // Guarantee a materialized activator so downstream gadgets can rely on it.
    let sort_input_df = if has_activator {
        input_df.clone()
    } else {
        // Ensure the output carries an activator even if the input did not.
        input_df
            .clone()
            .with_column(ACTIVATOR_COL_NAME, lit(true))
            .expect("sort exprs should accept synthetic activator")
    };

    // Verifier planning only needs shape/materialization metadata, not row values.
    // Avoid expensive sort planning here when we're in verifier mode.
    let output_hint = if skip_collection {
        crate::irs::nodes::hints::HintDF::new_materialized(sort_input_df)
    } else {
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
        // Respect the sort spec ordering by column name, falling back to schema order if needed.
        if !sort_specs.is_empty() {
            let mut ordered = Vec::with_capacity(sort_specs.len());
            for (name, asc, nulls_first) in sort_specs {
                let normalized = normalize_sort_name(name);
                if let Some(field) = data_fields
                    .iter()
                    .find(|field| normalize_sort_name(field.name()) == normalized)
                {
                    ordered.push(col(field.name()).sort(*asc, *nulls_first));
                }
            }
            if ordered.len() == data_fields.len() {
                sort_exprs.extend(ordered);
            } else {
                sort_exprs.extend(
                    data_fields
                        .iter()
                        .map(|field| col(field.name()).sort(true, true)),
                );
            }
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

        crate::irs::nodes::hints::HintDF::new_materialized(sorted_df)
    };
    // Keep row-id for deterministic tie-breaking, but do not materialize it.
    let mut should_materialize = IndexMap::new();
    for field in output_hint.data_frame().schema().fields() {
        let mat = field.name() != ROW_ID_COL_NAME;
        should_materialize.insert(field.clone(), mat);
    }
    let output_sort_exprs =
        crate::irs::nodes::hints::HintDF::new(output_hint.data_frame().clone(), should_materialize);
    gadget_payload.insert(OUTPUT_SORT_EXPRS.to_string(), output_sort_exprs);
    output_hint
}

fn populate_sort_gadget_table<B: SnarkBackend>(
    planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    sort_gadget_node_id: crate::irs::nodes::NodeId,
    output_sort_exprs: &crate::irs::nodes::hints::HintDF,
) {
    let mut payload = match planned_ir.payload_for_node(&sort_gadget_node_id) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    payload.insert(
        crate::irs::nodes::gadget::utils::contig_sort::TABLE_LABEL.to_string(),
        output_sort_exprs.clone(),
    );
    planned_ir.set_payload_for_node(
        sort_gadget_node_id,
        Some(PayloadStructure::GadgetPayload(payload)),
    );
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

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.sort_gadget.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
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

        let output_hint =
            populate_output_expr(&mut gadget_payload, &input_hint, &self.sort_specs, false);
        // Drop row-id from the input sort-exprs payload after it's been used for ordering.
        let sanitized_input = crate::irs::nodes::hints::strip_row_id_from_hint(&input_hint);
        gadget_payload.insert(INPUT_SORT_EXPRS.to_string(), sanitized_input);
        populate_sort_gadget_table(planned_ir, self.sort_gadget.id(), &output_hint);
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));
        Ok(())
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

        let output_hint =
            populate_output_expr(&mut gadget_payload, &input_hint, &self.sort_specs, true);
        let sanitized_input = crate::irs::nodes::hints::strip_row_id_from_hint(&input_hint);
        gadget_payload.insert(INPUT_SORT_EXPRS.to_string(), sanitized_input);
        populate_sort_gadget_table(planned_ir, self.sort_gadget.id(), &output_hint);
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));
        Ok(())
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

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(sort: Sort) -> Self {
        // Preserve column names so sort-spec ordering can be matched to hint schemas.
        let sort_specs: Vec<(String, bool, bool)> = sort
            .expr
            .iter()
            .map(|expr| {
                (
                    expr.expr.schema_name().to_string(),
                    expr.asc,
                    expr.nulls_first,
                )
            })
            .collect();
        // DataFusion sort expressions do not encode strictness, so default to true.
        let strict: bool = false;
        let sort_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::contig_sort::GadgetNode::new(
                crate::irs::nodes::gadget::utils::contig_sort::SortConfig::PerColumn(
                    crate::irs::nodes::gadget::utils::contig_sort::PerColumnConfig {
                        sort_specs: sort_specs.clone(),
                        strict,
                    },
                ),
            ),
        )));
        let remat_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::remat::GadgetNode::new(true),
        )));
        Self {
            sort_gadget,
            remat_gadget,
            sort_specs,
        }
    }
}

fn normalize_sort_name(name: &str) -> String {
    name.rsplit('.').next().unwrap_or(name).to_string()
}

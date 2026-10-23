use std::sync::Arc;

use arithmetic::{ACTIVATOR_FIELD, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_piop::{
    SnarkBackend,
    arithmetic::errors::DataTypeError,
    errors::{SnarkError, SnarkResult},
};
use datafusion::arrow::datatypes::{FieldRef, Schema};
use datafusion_expr::Sort;

use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{
            IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps,
            utils::{compaction, contig_sort},
        },
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
pub struct GadgetNode<B: SnarkBackend> {
    sort_gadget: Arc<Node<B>>,
    compaction_gadget: Arc<Node<B>>,
}

/// Plans the sort check from the input's key columns. Sorting them, which
/// the sort check does to plan its rotation and tie hints, gives the
/// output's key columns; the hint is virtual, so it commits nothing, and
/// `initialize_gadgets` replaces it with those output columns.
fn populate_sort_gadget_table<B: SnarkBackend>(
    planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    sort_gadget_node_id: crate::irs::nodes::NodeId,
    key_hint: &crate::irs::nodes::hints::HintDF,
) {
    let mut payload = match planned_ir.payload_for_node(&sort_gadget_node_id) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    payload.insert(contig_sort::TABLE_LABEL.to_string(), key_hint.clone());
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
        vec![self.sort_gadget.clone(), self.compaction_gadget.clone()]
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

        // Row-id was only needed for ordering: drop it from the input payload.
        let sanitized_input = crate::irs::nodes::hints::strip_row_id_from_hint(&input_hint);
        gadget_payload.insert(INPUT_SORT_EXPRS.to_string(), sanitized_input);
        populate_sort_gadget_table(planned_ir, self.sort_gadget.id(), &input_hint);
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

        let mut compaction_payload =
            match virtualized_ir.payload_for_node(&self.compaction_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
        if let Some(input) = payload.get(INPUT_LABEL).cloned() {
            compaction_payload.insert(compaction::INPUT_LABEL.to_string(), input);
        }
        if let Some(output) = payload.get(OUTPUT_LABEL).cloned() {
            compaction_payload.insert(compaction::OUTPUT_LABEL.to_string(), output);
        }
        if !compaction_payload.is_empty() {
            virtualized_ir.set_payload_for_node(
                self.compaction_gadget.id(),
                Some(PayloadStructure::GadgetPayload(compaction_payload)),
            );
        }

        if let (Some(output), Some(keys)) =
            (payload.get(OUTPUT_LABEL), payload.get(INPUT_SORT_EXPRS))
        {
            let mut sort_payload = match virtualized_ir.payload_for_node(&self.sort_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            sort_payload.insert(
                contig_sort::TABLE_LABEL.to_string(),
                output_sort_keys_prover(output, keys)?,
            );
            if let Some(count) = payload.get(contig_sort::ACTIVE_ROWS_LABEL) {
                sort_payload.insert(contig_sort::ACTIVE_ROWS_LABEL.to_string(), count.clone());
            }
            virtualized_ir.set_payload_for_node(
                self.sort_gadget.id(),
                Some(PayloadStructure::GadgetPayload(sort_payload)),
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
        let gadget_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        let input_hint = match gadget_payload.get(INPUT_SORT_EXPRS) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };

        populate_sort_gadget_table(planned_ir, self.sort_gadget.id(), &input_hint);
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

        let mut compaction_payload =
            match virtualized_ir.payload_for_node(&self.compaction_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
        if let Some(input) = payload.get(INPUT_LABEL).cloned() {
            compaction_payload.insert(compaction::INPUT_LABEL.to_string(), input);
        }
        if let Some(output) = payload.get(OUTPUT_LABEL).cloned() {
            compaction_payload.insert(compaction::OUTPUT_LABEL.to_string(), output);
        }
        if !compaction_payload.is_empty() {
            virtualized_ir.set_payload_for_node(
                self.compaction_gadget.id(),
                Some(PayloadStructure::GadgetPayload(compaction_payload)),
            );
        }

        if let (Some(output), Some(keys)) =
            (payload.get(OUTPUT_LABEL), payload.get(INPUT_SORT_EXPRS))
        {
            let mut sort_payload = match virtualized_ir.payload_for_node(&self.sort_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            sort_payload.insert(
                contig_sort::TABLE_LABEL.to_string(),
                output_sort_keys_verifier(output, keys)?,
            );
            if let Some(count) = payload.get(contig_sort::ACTIVE_ROWS_LABEL) {
                sort_payload.insert(contig_sort::ACTIVE_ROWS_LABEL.to_string(), count.clone());
            }
            virtualized_ir.set_payload_for_node(
                self.sort_gadget.id(),
                Some(PayloadStructure::GadgetPayload(sort_payload)),
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
        // Column names are kept so the sort-spec order can be matched to hint schemas.
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
        // DataFusion sort expressions do not encode strictness, so the sort
        // gadget is non-strict.
        let strict: bool = false;
        let sort_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::utils::contig_sort::GadgetNode::new(
                crate::irs::nodes::utils::contig_sort::SortConfig::PerColumn(
                    crate::irs::nodes::utils::contig_sort::PerColumnConfig { sort_specs, strict },
                ),
            ),
        )));
        let compaction_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::utils::compaction::GadgetNode::new(),
        )));
        Self {
            sort_gadget,
            compaction_gadget,
        }
    }
}

/// The sort check's table: the output's sort-key columns in key order plus
/// its activator (paper PIOP 14, step 3). `keys` names the key columns,
/// with every encoded segment of a string key; a key that is not an output
/// column, such as a computed expression, is not supported.
fn output_sort_keys_prover<B: SnarkBackend>(
    output: &TrackedTable<B>,
    keys: &TrackedTable<B>,
) -> SnarkResult<TrackedTable<B>> {
    let output_polys = output.tracked_polys();
    let key_polys = keys.tracked_polys();
    let mut polys = IndexMap::new();
    for idx in keys.data_tracked_polys_indices() {
        let (key_field, _) = key_polys.get_index(idx).expect("key column index");
        let (field, poly) = output_column(&output_polys, key_field.name())?;
        polys.insert(field.clone(), poly.clone());
    }
    if let Some(activator) = output.activator_tracked_poly() {
        polys.insert(ACTIVATOR_FIELD.clone(), activator);
    }
    Ok(TrackedTable::new(
        Some(schema_of(polys.keys())),
        polys,
        output.log_size(),
    ))
}

fn output_sort_keys_verifier<B: SnarkBackend>(
    output: &TrackedTableOracle<B>,
    keys: &TrackedTableOracle<B>,
) -> SnarkResult<TrackedTableOracle<B>> {
    let output_oracles = output.tracked_oracles();
    let key_oracles = keys.tracked_oracles();
    let mut oracles = IndexMap::new();
    for idx in keys.data_tracked_oracles_indices() {
        let (key_field, _) = key_oracles.get_index(idx).expect("key column index");
        let (field, oracle) = output_column(&output_oracles, key_field.name())?;
        oracles.insert(field.clone(), oracle.clone());
    }
    if let Some(activator) = output.activator_tracked_poly() {
        oracles.insert(ACTIVATOR_FIELD.clone(), activator);
    }
    Ok(TrackedTableOracle::new(
        Some(schema_of(oracles.keys())),
        oracles,
        output.log_size(),
    ))
}

fn output_column<'a, T>(
    columns: &'a IndexMap<FieldRef, T>,
    key_name: &str,
) -> SnarkResult<(&'a FieldRef, &'a T)> {
    let key = normalize_sort_name(key_name);
    columns
        .iter()
        .find(|(field, _)| normalize_sort_name(field.name()) == key)
        .ok_or_else(|| {
            SnarkError::DataTypeError(DataTypeError::NotSupported(format!(
                "ORDER BY key `{key_name}` is not an output column"
            )))
        })
}

fn schema_of<'a>(fields: impl Iterator<Item = &'a FieldRef>) -> Schema {
    Schema::new(
        fields
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>(),
    )
}

fn normalize_sort_name(name: &str) -> String {
    name.rsplit('.').next().unwrap_or(name).to_string()
}

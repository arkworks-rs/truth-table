use std::{collections::HashSet, sync::Arc};

use arithmetic::{ACTIVATOR_COL_NAME, is_system_column};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::DataType;
use datafusion_expr::{Expr, Sort};

use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps, utils::remat},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};
#[cfg(test)]
mod tests;

pub const INPUT_LABEL: &str = "__input__";
pub const OUTPUT_LABEL: &str = "__output__";
pub const OUTPUT_SORT_EXPRS: &str = "__output_sort_exprs__";
pub struct GadgetNode<B: SnarkBackend> {
    sort_gadget: Arc<Node<B>>,
    remat_gadget: Arc<Node<B>>,
    sort_key_count: usize,
    validation_error: Option<String>,
}

pub(super) fn is_supported_sort_type(data_type: &DataType) -> bool {
    matches!(
        data_type,
        DataType::Int8
            | DataType::Int16
            | DataType::Int32
            | DataType::Int64
            | DataType::UInt8
            | DataType::UInt16
            | DataType::UInt32
            | DataType::UInt64
            | DataType::Date32
    )
}

fn missing_sort_keys() -> ark_piop::errors::SnarkError {
    ark_piop::errors::SnarkError::Artifact(
        "ORDER BY output sort-key payload is missing".to_string(),
    )
}

fn missing_order_table(label: &str) -> ark_piop::errors::SnarkError {
    ark_piop::errors::SnarkError::Artifact(format!(
        "ORDER BY row-permutation payload `{label}` is missing"
    ))
}

fn invalid_sort(message: String) -> ark_piop::errors::SnarkError {
    ark_piop::errors::SnarkError::Artifact(message)
}

fn checked_output_hint(
    payload: &IndexMap<String, crate::irs::nodes::hints::HintDF>,
    expected_keys: usize,
) -> ark_piop::errors::SnarkResult<&crate::irs::nodes::hints::HintDF> {
    // This checks only the planning shape. Exact tracker/oracle identity is
    // enforced later when the Sort LP selects keys from its tracked output.
    let hint = payload
        .get(OUTPUT_SORT_EXPRS)
        .ok_or_else(missing_sort_keys)?;
    let actual_keys = hint
        .data_frame()
        .schema()
        .fields()
        .iter()
        .filter(|field| !is_system_column(field.name()))
        .count();
    if actual_keys != expected_keys {
        return Err(invalid_sort(format!(
            "ORDER BY output sort-key hint contains {actual_keys} keys, expected {expected_keys}"
        )));
    }
    let activators = hint
        .data_frame()
        .schema()
        .fields()
        .iter()
        .filter(|field| field.name() == ACTIVATOR_COL_NAME)
        .collect::<Vec<_>>();
    if activators.len() != 1 || activators[0].data_type() != &DataType::Boolean {
        return Err(invalid_sort(
            "ORDER BY output sort-key hint must contain one Boolean activator".to_string(),
        ));
    }
    Ok(hint)
}

/// Return the deliberately small ORDER BY fragment whose key values are
/// currently tied to constrained output expressions.
///
/// In particular, several expression nodes materialize a witness without a
/// gadget proving its SQL semantics. Accepting those nodes here would let the
/// prover sort an unrelated column. Qualified columns with the same terminal
/// name are also rejected because ContiguousSort currently identifies key
/// columns by that terminal name.
pub(super) fn validate_sort(sort: &Sort) -> Result<(), String> {
    if sort.expr.is_empty() {
        return Err("ORDER BY requires at least one proved key".to_string());
    }
    if sort.fetch.is_some() {
        return Err(
            "ORDER BY with an embedded fetch is unsupported; normalize it to a separately proved LIMIT"
                .to_string(),
        );
    }

    let mut names = HashSet::with_capacity(sort.expr.len());
    for sort_expr in &sort.expr {
        let Expr::Column(column) = &sort_expr.expr else {
            return Err(format!(
                "unsupported ORDER BY key `{}`; only direct column keys are currently proved",
                sort_expr.expr
            ));
        };
        if is_system_column(column.name()) {
            return Err(format!(
                "internal system column `{column}` cannot be an ORDER BY key"
            ));
        }
        let (_, field) = sort
            .input
            .schema()
            .qualified_field_from_column(column)
            .map_err(|error| {
                format!("ORDER BY key `{column}` does not resolve uniquely: {error}")
            })?;
        if field.is_nullable() {
            return Err(format!(
                "nullable ORDER BY key `{column}` is unsupported until NULL ordering is proved"
            ));
        }
        if !is_supported_sort_type(field.data_type()) {
            return Err(format!(
                "unsupported ORDER BY key type `{}` for `{column}`; only bounded integer/date keys are currently proved",
                field.data_type()
            ));
        }
        // ContiguousSort identifies columns by the terminal segment of their
        // field name. Quoted identifiers containing a dot cannot currently be
        // represented without a collision, so reject them explicitly.
        if column.name.contains('.') {
            return Err(format!(
                "unsupported ORDER BY key name `{}`; dots in key field names are not currently proved",
                column.name
            ));
        }
        if !names.insert(column.name.clone()) {
            return Err(format!(
                "ambiguous ORDER BY key `{}`; duplicate unqualified key names are unsupported",
                column.name
            ));
        }
    }
    Ok(())
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
        crate::irs::nodes::utils::contig_sort::TABLE_LABEL.to_string(),
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
        vec![self.sort_gadget.clone(), self.remat_gadget.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        self.ensure_valid()?;
        let gadget_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Err(missing_sort_keys()),
        };
        let output_hint = checked_output_hint(&gadget_payload, self.sort_key_count)?.clone();

        // The key table is virtual. Only rotation/tie/difference auxiliaries
        // are materialized by the child; initialization supplies the actual keys.
        populate_sort_gadget_table(planned_ir, self.sort_gadget.id(), &output_hint);
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));
        Ok(())
    }
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        self.ensure_valid()
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        self.ensure_valid()?;
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Err(missing_sort_keys());
        };

        let keys = payload
            .get(OUTPUT_SORT_EXPRS)
            .cloned()
            .ok_or_else(missing_sort_keys)?;
        let mut sort_payload = match virtualized_ir.payload_for_node(&self.sort_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        sort_payload.insert(
            crate::irs::nodes::utils::contig_sort::TABLE_LABEL.to_string(),
            keys,
        );
        virtualized_ir.set_payload_for_node(
            self.sort_gadget.id(),
            Some(PayloadStructure::GadgetPayload(sort_payload)),
        );

        let input = payload
            .get(INPUT_LABEL)
            .cloned()
            .ok_or_else(|| missing_order_table(INPUT_LABEL))?;
        let output = payload
            .get(OUTPUT_LABEL)
            .cloned()
            .ok_or_else(|| missing_order_table(OUTPUT_LABEL))?;
        let mut remat_payload = match virtualized_ir.payload_for_node(&self.remat_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        remat_payload.insert(remat::INPUT_LABEL.to_string(), input);
        remat_payload.insert(remat::OUTPUT_LABEL.to_string(), output);
        virtualized_ir.set_payload_for_node(
            self.remat_gadget.id(),
            Some(PayloadStructure::GadgetPayload(remat_payload)),
        );
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        self.ensure_valid()?;
        let gadget_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Err(missing_sort_keys()),
        };
        let output_hint = checked_output_hint(&gadget_payload, self.sort_key_count)?.clone();

        populate_sort_gadget_table(planned_ir, self.sort_gadget.id(), &output_hint);
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));
        Ok(())
    }
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        self.ensure_valid()
    }
    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        self.ensure_valid()?;
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Err(missing_sort_keys());
        };

        // Mirror the prover binding: Sortcheck must consume the same oracle
        // expressions as the committed output, never a separate sorted witness.
        let keys = payload
            .get(OUTPUT_SORT_EXPRS)
            .cloned()
            .ok_or_else(missing_sort_keys)?;
        let mut sort_payload = match virtualized_ir.payload_for_node(&self.sort_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        sort_payload.insert(
            crate::irs::nodes::utils::contig_sort::TABLE_LABEL.to_string(),
            keys,
        );
        virtualized_ir.set_payload_for_node(
            self.sort_gadget.id(),
            Some(PayloadStructure::GadgetPayload(sort_payload)),
        );

        let input = payload
            .get(INPUT_LABEL)
            .cloned()
            .ok_or_else(|| missing_order_table(INPUT_LABEL))?;
        let output = payload
            .get(OUTPUT_LABEL)
            .cloned()
            .ok_or_else(|| missing_order_table(OUTPUT_LABEL))?;
        let mut remat_payload = match virtualized_ir.payload_for_node(&self.remat_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        remat_payload.insert(remat::INPUT_LABEL.to_string(), input);
        remat_payload.insert(remat::OUTPUT_LABEL.to_string(), output);
        virtualized_ir.set_payload_for_node(
            self.remat_gadget.id(),
            Some(PayloadStructure::GadgetPayload(remat_payload)),
        );
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
        self.ensure_valid()
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        self.ensure_valid()
    }

    fn verify(
        &self,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        self.ensure_valid()
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
        let validation_error = validate_sort(&sort).err();
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
        // SQL ORDER BY permits ties.
        let strict: bool = false;
        let sort_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::utils::contig_sort::GadgetNode::new(
                crate::irs::nodes::utils::contig_sort::SortConfig::PerColumn(
                    crate::irs::nodes::utils::contig_sort::PerColumnConfig {
                        sort_specs: sort_specs.clone(),
                        strict,
                    },
                ),
            ),
        )));
        let remat_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::utils::remat::GadgetNode::new(true),
        )));
        Self {
            sort_gadget,
            remat_gadget,
            sort_key_count: sort.expr.len(),
            validation_error,
        }
    }

    fn ensure_valid(&self) -> ark_piop::errors::SnarkResult<()> {
        match &self.validation_error {
            Some(message) => Err(invalid_sort(message.clone())),
            None => Ok(()),
        }
    }
}

use std::sync::Arc;

use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::{One, Zero};
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    verifier::errors::VerifierError,
};
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{
            IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps,
            utils::{bool, field_to_usize, perm},
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
pub struct GadgetNode<B: SnarkBackend> {
    /// Also prove that the output activator is `C_{µ,s}` for the output's
    /// active-row count `s` (paper PIOP 14, step 1). The sort check compares
    /// only adjacent active rows, so a gap in the activator hides a pair.
    contiguous: bool,
    bool_check_gadget: Arc<Node<B>>,
    perm_check_gadget: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "CompactionCheck".to_string()
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
        vec![
            self.bool_check_gadget.clone(),
            self.perm_check_gadget.clone(),
        ]
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
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };

        let input = payload
            .get(INPUT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Compaction gadget missing {}", INPUT_LABEL));
        let output = payload
            .get(OUTPUT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Compaction gadget missing {}", OUTPUT_LABEL));

        populate_bool_payload_prover(&self.bool_check_gadget, &output, virtualized_ir)?;
        populate_perm_payloads_prover(&self.perm_check_gadget, &input, &output, virtualized_ir)?;
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
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
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };

        let input = payload
            .get(INPUT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Compaction gadget missing {}", INPUT_LABEL));
        let output = payload
            .get(OUTPUT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Compaction gadget missing {}", OUTPUT_LABEL));

        populate_bool_payload_verifier(&self.bool_check_gadget, &output, virtualized_ir)?;
        populate_perm_payloads_verifier(&self.perm_check_gadget, &input, &output, virtualized_ir)?;
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> SnarkResult<()> {
        if !self.contiguous {
            return Ok(());
        }
        let output = output_table(gadget_ready_ir.payload_for_node(&id))?;
        let activator = output
            .activator_tracked_poly()
            .ok_or_else(|| check_failed("the output has no activator"))?;
        let active_count = activator
            .evaluations()
            .iter()
            .filter(|value| value.is_one())
            .count();
        // `s` picks the public prefix the zerocheck compares against, so it
        // is committed (and so in the transcript) before any challenge; a
        // miscellaneous proof field is not.
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
            0,
            vec![B::F::from(active_count as u64)],
        ))?;
        let prefix = activator
            .tracker()
            .borrow_mut()
            .get_or_build_contig_one_poly(output.log_size(), active_count)?;
        prover.add_mv_zerocheck_claim((&activator - &prefix).id())?;
        Ok(())
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> SnarkResult<()> {
        if !self.contiguous {
            return Ok(());
        }
        let output = output_table(gadget_ready_ir.payload_for_node(&id))?;
        let activator = output
            .activator_tracked_poly()
            .ok_or_else(|| check_failed("the output has no activator"))?;
        let evaluations = activator.evaluations();
        let active_count = evaluations
            .iter()
            .take_while(|value| value.is_one())
            .count();
        if !evaluations[active_count..]
            .iter()
            .all(|value| value.is_zero())
        {
            return Err(SnarkError::ProverError(
                ark_piop::prover::errors::ProverError::HonestProverError(
                    ark_piop::prover::errors::HonestProverError::FalseClaim,
                ),
            ));
        }
        Ok(())
    }

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> SnarkResult<()> {
        if !self.contiguous {
            return Ok(());
        }
        let output = output_table(gadget_ready_ir.payload_for_node(&id))?;
        let activator = output
            .activator_tracked_poly()
            .ok_or_else(|| check_failed("the output has no activator"))?;
        let count = verifier.track_next_mv_com()?;
        let active_count = match count.as_constant() {
            Some(value) if count.log_size() == 0 => {
                field_to_usize(value, "the compaction output's active-row count")?
            }
            _ => {
                return Err(check_failed(
                    "the active-row count is not a committed scalar",
                ));
            }
        };
        let prefix = activator
            .tracker()
            .borrow_mut()
            .get_or_build_contig_one_poly(output.log_size(), active_count)?;
        verifier.add_mv_zerocheck_claim((&activator - &prefix).id());
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
    pub fn new(contiguous: bool) -> Self
    where
        Self: Sized,
    {
        let bool_check_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::utils::bool::GadgetNode::new(),
        )));

        let perm_check_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::utils::perm::GadgetNode::new(),
        )));
        Self {
            contiguous,
            bool_check_gadget,
            perm_check_gadget,
        }
    }
}

fn output_table<T: Clone>(payload: Option<&PayloadStructure<T>>) -> SnarkResult<T> {
    match payload {
        Some(PayloadStructure::GadgetPayload(payload)) => payload
            .get(OUTPUT_LABEL)
            .cloned()
            .ok_or_else(|| check_failed("the payload has no output table")),
        _ => Err(check_failed("the gadget has no payload")),
    }
}

fn check_failed(msg: &str) -> SnarkError {
    SnarkError::VerifierError(VerifierError::VerifierCheckFailed(format!(
        "CompactionCheck: {msg}"
    )))
}

fn bool_table_from_output_prover<B: SnarkBackend>(output: &TrackedTable<B>) -> TrackedTable<B> {
    let activator = output
        .activator_tracked_poly()
        .expect("Compaction output should carry an activator column");
    // Use a non-system field name so BoolCheck treats it as data.
    let field = Arc::new(Field::new("data", DataType::Boolean, false));
    let mut tracked_polys = IndexMap::new();
    tracked_polys.insert(field.clone(), activator);
    let schema = Some(Schema::new(vec![field.as_ref().clone()]));
    TrackedTable::new(schema, tracked_polys, output.log_size())
}

fn bool_table_from_output_verifier<B: SnarkBackend>(
    output: &TrackedTableOracle<B>,
) -> TrackedTableOracle<B> {
    let activator = output
        .activator_tracked_poly()
        .expect("Compaction output should carry an activator column");
    // Use a non-system field name so BoolCheck treats it as data.
    let field = Arc::new(Field::new("data", DataType::Boolean, false));
    let mut tracked_oracles = IndexMap::new();
    tracked_oracles.insert(field.clone(), activator);
    let schema = Some(Schema::new(vec![field.as_ref().clone()]));
    TrackedTableOracle::new(schema, tracked_oracles, output.log_size())
}

fn populate_bool_payload_prover<B: SnarkBackend>(
    bool_gadget: &Arc<Node<B>>,
    output: &TrackedTable<B>,
    virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let bool_table = bool_table_from_output_prover(output);
    let mut bool_payload = match virtualized_ir.payload_for_node(&bool_gadget.id()) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    bool_payload.insert(bool::TABLE_LABEL.to_string(), bool_table);
    virtualized_ir.set_payload_for_node(
        bool_gadget.id(),
        Some(PayloadStructure::GadgetPayload(bool_payload)),
    );
    Ok(())
}

fn populate_bool_payload_verifier<B: SnarkBackend>(
    bool_gadget: &Arc<Node<B>>,
    output: &TrackedTableOracle<B>,
    virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let bool_table = bool_table_from_output_verifier(output);
    let mut bool_payload = match virtualized_ir.payload_for_node(&bool_gadget.id()) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    bool_payload.insert(bool::TABLE_LABEL.to_string(), bool_table);
    virtualized_ir.set_payload_for_node(
        bool_gadget.id(),
        Some(PayloadStructure::GadgetPayload(bool_payload)),
    );
    Ok(())
}

fn populate_perm_payloads_prover<B: SnarkBackend>(
    perm_gadget: &Arc<Node<B>>,
    input: &TrackedTable<B>,
    output: &TrackedTable<B>,
    virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let aligned_output = restrict_table_to_reference_columns(output, input);
    let mut perm_payload = match virtualized_ir.payload_for_node(&perm_gadget.id()) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    perm_payload.insert(perm::LEFT_LABEL.to_string(), input.clone());
    perm_payload.insert(perm::RIGHT_LABEL.to_string(), aligned_output);
    virtualized_ir.set_payload_for_node(
        perm_gadget.id(),
        Some(PayloadStructure::GadgetPayload(perm_payload)),
    );
    Ok(())
}

fn populate_perm_payloads_verifier<B: SnarkBackend>(
    perm_gadget: &Arc<Node<B>>,
    input: &TrackedTableOracle<B>,
    output: &TrackedTableOracle<B>,
    virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let aligned_output = restrict_table_oracle_to_reference_columns(output, input);
    let mut perm_payload = match virtualized_ir.payload_for_node(&perm_gadget.id()) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    perm_payload.insert(perm::LEFT_LABEL.to_string(), input.clone());
    perm_payload.insert(perm::RIGHT_LABEL.to_string(), aligned_output);
    virtualized_ir.set_payload_for_node(
        perm_gadget.id(),
        Some(PayloadStructure::GadgetPayload(perm_payload)),
    );
    Ok(())
}

/// Restricts `table` to the columns `reference` carries.
///
/// This selects columns without reordering them:
/// `tracked_subtable_by_indices` rebuilds the subtable in the table's own
/// `tracked_cols` order. The two sides need not share a column order, since
/// the permutation gadget folds both by name
/// (`utils::perm::should_fold_by_names`).
fn restrict_table_to_reference_columns<B: SnarkBackend>(
    table: &TrackedTable<B>,
    reference: &TrackedTable<B>,
) -> TrackedTable<B> {
    let table_fields: Vec<FieldRef> = table.tracked_polys().keys().cloned().collect();
    let reference_fields: Vec<FieldRef> = reference.tracked_polys().keys().cloned().collect();
    let indices = reference_column_indices(
        &table_fields,
        &reference_fields,
        table.data_tracked_polys_indices(),
    );
    table.tracked_subtable_by_indices(&indices)
}

fn restrict_table_oracle_to_reference_columns<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    reference: &TrackedTableOracle<B>,
) -> TrackedTableOracle<B> {
    let table_fields: Vec<FieldRef> = table.tracked_oracles().keys().cloned().collect();
    let reference_fields: Vec<FieldRef> = reference.tracked_oracles().keys().cloned().collect();
    let indices = reference_column_indices(
        &table_fields,
        &reference_fields,
        table.data_tracked_oracles_indices(),
    );
    table.tracked_subtable_by_indices(&indices)
}

/// Locates each of `reference`'s data columns within `table`, as indices into
/// `table`'s flat view.
///
/// Both inputs are flat views (`tracked_polys` / `tracked_oracles` key order),
/// the index space of `tracked_subtable_by_indices` and of `fallback_indices`.
/// Schemas would mix two index spaces: a schema lists only user-visible
/// fields, while the flat view also expands every arithmetization segment
/// (`__length`, ...) and carries `__activator__`.
///
/// Falls back to `fallback_indices`, every data column, whenever the
/// correspondence is ambiguous.
fn reference_column_indices(
    table_fields: &[FieldRef],
    reference_fields: &[FieldRef],
    fallback_indices: Vec<usize>,
) -> Vec<usize> {
    let reference_data_fields: Vec<_> = reference_fields
        .iter()
        .filter(|field| !arithmetic::is_system_column(field.name()))
        .cloned()
        .collect();

    if reference_data_fields.len() > fallback_indices.len() {
        return fallback_indices;
    }

    let mut aligned = Vec::with_capacity(reference_data_fields.len());
    for ref_field in &reference_data_fields {
        let exact_matches: Vec<_> = table_fields
            .iter()
            .enumerate()
            .filter(|(_, field)| !arithmetic::is_system_column(field.name()) && *field == ref_field)
            .map(|(idx, _)| idx)
            .collect();
        if exact_matches.len() == 1 {
            aligned.push(exact_matches[0]);
            continue;
        }

        let name_matches: Vec<_> = table_fields
            .iter()
            .enumerate()
            .filter(|(_, field)| {
                !arithmetic::is_system_column(field.name()) && field.name() == ref_field.name()
            })
            .map(|(idx, _)| idx)
            .collect();
        if name_matches.len() == 1 {
            aligned.push(name_matches[0]);
            continue;
        }

        return fallback_indices;
    }

    aligned
}

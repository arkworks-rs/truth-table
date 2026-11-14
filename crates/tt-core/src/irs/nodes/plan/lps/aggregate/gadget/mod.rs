use std::collections::BTreeSet;
use std::sync::Arc;

use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::{One, PrimeField};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{DataType, Field};
use datafusion_expr::Aggregate;
use indexmap::IndexMap;

use crate::irs::functional_dependencies;
use crate::irs::nodes::utils::contig_sort::compared_columns;
use crate::irs::nodes::utils::{bool, supp};
use crate::irs::nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps};
use crate::irs::payloads::PayloadStructure;
use crate::irs::unique_keys;
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;

pub const INPUT_LABEL: &str = "__input__";
pub const OUTPUT_LABEL: &str = "__output__";
const PREDICATE_COL_NAME: &str = "predicate";

pub struct GadgetNode<B: SnarkBackend> {
    supp_gadget: Option<Arc<Node<B>>>,
    bool_gadget: Option<Arc<Node<B>>>,
    aggregate: Aggregate,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Aggregate".to_string()
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
        let mut children = Vec::with_capacity(2);
        children.extend(self.supp_gadget.iter().cloned());
        children.extend(self.bool_gadget.iter().cloned());
        children
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        if !self.has_groups() {
            return Ok(());
        }
        let aggregate_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };

        let input_hint = match aggregate_payload.get(INPUT_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };
        let output_hint = match aggregate_payload.get(OUTPUT_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };

        let mut supp_payload =
            match planned_ir.payload_for_node(&self.supp_gadget.as_ref().unwrap().id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };

        supp_payload.insert(supp::ORIG_LABEL.to_string(), input_hint);
        supp_payload.insert(supp::SUPER_LABEL.to_string(), output_hint);

        planned_ir.set_payload_for_node(
            self.supp_gadget.as_ref().unwrap().id(),
            Some(PayloadStructure::GadgetPayload(supp_payload)),
        );
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
        if !self.has_groups() {
            return Ok(());
        }
        let gadget_payload = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => panic!("Expected gadget payload for aggregate node"),
        };

        let output_table = gadget_payload
            .get(OUTPUT_LABEL)
            .cloned()
            .expect("Expected aggregate output table");

        if let Some(supp_gadget) = &self.supp_gadget {
            let input_table = gadget_payload
                .get(INPUT_LABEL)
                .cloned()
                .expect("Expected grouped aggregate input table");
            let mut supp_payload = match virtualized_ir.payload_for_node(&supp_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };

            supp_payload.insert(supp::ORIG_LABEL.to_string(), input_table);
            supp_payload.insert(supp::SUPER_LABEL.to_string(), output_table.clone());
            virtualized_ir.set_payload_for_node(
                supp_gadget.id(),
                Some(PayloadStructure::GadgetPayload(supp_payload)),
            );
        }

        if let Some(bool_gadget) = &self.bool_gadget {
            let bool_table = bool_table_from_output_prover(&output_table);
            let mut bool_payload = match virtualized_ir.payload_for_node(&bool_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            bool_payload.insert(bool::TABLE_LABEL.to_string(), bool_table);
            virtualized_ir.set_payload_for_node(
                bool_gadget.id(),
                Some(PayloadStructure::GadgetPayload(bool_payload)),
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
        if !self.has_groups() {
            return Ok(());
        }
        let aggregate_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };

        let input_hint = match aggregate_payload.get(INPUT_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };
        let output_hint = match aggregate_payload.get(OUTPUT_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };

        let mut supp_payload =
            match planned_ir.payload_for_node(&self.supp_gadget.as_ref().unwrap().id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };

        supp_payload.insert(supp::ORIG_LABEL.to_string(), input_hint);
        supp_payload.insert(supp::SUPER_LABEL.to_string(), output_hint);

        planned_ir.set_payload_for_node(
            self.supp_gadget.as_ref().unwrap().id(),
            Some(PayloadStructure::GadgetPayload(supp_payload)),
        );
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
        if !self.has_groups() {
            return Ok(());
        }
        let gadget_payload = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => panic!("Expected gadget payload for aggregate node"),
        };

        let output_table = gadget_payload
            .get(OUTPUT_LABEL)
            .cloned()
            .expect("Expected aggregate output table");

        if let Some(supp_gadget) = &self.supp_gadget {
            let input_table = gadget_payload
                .get(INPUT_LABEL)
                .cloned()
                .expect("Expected grouped aggregate input table");
            let mut supp_payload = match virtualized_ir.payload_for_node(&supp_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };

            supp_payload.insert(supp::ORIG_LABEL.to_string(), input_table);
            supp_payload.insert(supp::SUPER_LABEL.to_string(), output_table.clone());
            virtualized_ir.set_payload_for_node(
                supp_gadget.id(),
                Some(PayloadStructure::GadgetPayload(supp_payload)),
            );
        }

        if let Some(bool_gadget) = &self.bool_gadget {
            let bool_table = bool_table_from_output_verifier(&output_table);
            let mut bool_payload = match virtualized_ir.payload_for_node(&bool_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            bool_payload.insert(bool::TABLE_LABEL.to_string(), bool_table);
            virtualized_ir.set_payload_for_node(
                bool_gadget.id(),
                Some(PayloadStructure::GadgetPayload(bool_payload)),
            );
        }
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        if self.has_groups() {
            let Some(PayloadStructure::GadgetPayload(payload)) =
                gadget_ready_ir.payload_for_node(&id)
            else {
                panic!("Expected gadget payload for grouped aggregate");
            };
            let activator = |label: &str| {
                payload
                    .get(label)
                    .and_then(|table| table.activator_tracked_poly())
                    .unwrap_or_else(|| panic!("Grouped aggregate {label} must carry an activator"))
            };
            let (input_act, output_act) = (activator(INPUT_LABEL), activator(OUTPUT_LABEL));
            let outside_input = &output_act
                * &input_act
                    .mul_scalar_poly(-B::F::one())
                    .add_scalar_poly(B::F::one());
            prover.add_mv_zerocheck_claim(outside_input.id())?;
        }
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
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        if self.has_groups() {
            let Some(PayloadStructure::GadgetPayload(payload)) =
                gadget_ready_ir.payload_for_node(&id)
            else {
                panic!("Expected gadget payload for grouped aggregate");
            };
            let activator = |label: &str| {
                payload
                    .get(label)
                    .and_then(|table| table.activator_tracked_poly())
                    .unwrap_or_else(|| panic!("Grouped aggregate {label} must carry an activator"))
            };
            let (input_act, output_act) = (activator(INPUT_LABEL), activator(OUTPUT_LABEL));
            let outside_input = &output_act
                * &input_act
                    .mul_scalar_oracle(-B::F::one())
                    .add_scalar_oracle(B::F::one());
            verifier.add_mv_zerocheck_claim(outside_input.id());
        }
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
    pub fn new(aggregate: Aggregate) -> Self {
        let has_groups = !aggregate.group_expr.is_empty();
        // The output's group columns copy the input's at a subset of its
        // active rows, so they hold no duplicate when they contain an input key.
        let group_columns = aggregate
            .group_expr
            .iter()
            .filter_map(|expr| unique_keys::copied_input_index(expr, aggregate.input.schema()))
            .collect();
        let groups_are_unique = unique_keys::contains_unique_key(&aggregate.input, &group_columns);
        let supp_gadget = has_groups.then(|| {
            let nodup_key = (!groups_are_unique)
                .then(|| distinctness_key::<B::F>(&aggregate))
                .flatten();
            Arc::new(Node::<B>::Gadget(Arc::new(
                crate::irs::nodes::utils::supp::GadgetNode::new(groups_are_unique, nodup_key),
            )))
        });
        let bool_gadget = has_groups.then(|| {
            Arc::new(Node::<B>::Gadget(Arc::new(
                crate::irs::nodes::utils::bool::GadgetNode::<B>::new(),
            )))
        });
        Self {
            supp_gadget,
            aggregate,
            bool_gadget,
        }
    }

    fn has_groups(&self) -> bool {
        !self.aggregate.group_expr.is_empty()
    }
}

/// The names of the group columns, cheapest for the distinct sort, that fix
/// every group column through the input's functional dependencies, or `None`
/// when that takes them all. The output's group columns copy input rows, so
/// its rows are distinct on these exactly when they are distinct.
fn distinctness_key<F: PrimeField>(aggregate: &Aggregate) -> Option<BTreeSet<String>> {
    // Subsets are enumerated; past this many group columns, compare them all.
    const MAX_GROUPS: usize = 16;
    let input = aggregate.input.schema();
    let copies: Vec<Option<usize>> = aggregate
        .group_expr
        .iter()
        .map(|expr| unique_keys::copied_input_index(expr, input))
        .collect();
    if copies.len() > MAX_GROUPS {
        return None;
    }
    let dependencies = functional_dependencies::dependencies(&aggregate.input);
    let copied: BTreeSet<usize> = copies.iter().flatten().copied().collect();
    let cost = |position: usize| {
        compared_columns::<F>(aggregate.schema.field(position)).unwrap_or(usize::MAX / MAX_GROUPS)
    };
    let mut best: Option<(usize, Vec<usize>)> = None;
    for subset in 1u32..(1 << copies.len()) {
        // A group expression that copies no input column is always compared.
        let key: Vec<usize> = (0..copies.len())
            .filter(|&position| subset >> position & 1 == 1 || copies[position].is_none())
            .collect();
        let from: BTreeSet<usize> = key
            .iter()
            .filter_map(|&position| copies[position])
            .collect();
        if !functional_dependencies::closure(&dependencies, &from).is_superset(&copied) {
            continue;
        }
        let key_cost = key.iter().map(|&position| cost(position)).sum();
        if best.as_ref().is_none_or(|(best_cost, best_key)| {
            (key_cost, key.len()) < (*best_cost, best_key.len())
        }) {
            best = Some((key_cost, key));
        }
    }
    best.filter(|(_, key)| key.len() < copies.len())
        .map(|(_, key)| {
            key.iter()
                .map(|&position| aggregate.schema.field(position).name().clone())
                .collect()
        })
}

fn bool_table_from_output_prover<B: SnarkBackend>(output: &TrackedTable<B>) -> TrackedTable<B> {
    let predicate_poly = output
        .activator_tracked_poly()
        .expect("Aggregate output should carry an activator column");
    let predicate_field = Arc::new(Field::new(PREDICATE_COL_NAME, DataType::Boolean, false));
    TrackedTable::single_column_with_activator(predicate_field, predicate_poly, None)
}

fn bool_table_from_output_verifier<B: SnarkBackend>(
    output: &TrackedTableOracle<B>,
) -> TrackedTableOracle<B> {
    let predicate_oracle = output
        .activator_tracked_poly()
        .expect("Aggregate output should carry an activator column");
    let predicate_field = Arc::new(Field::new(PREDICATE_COL_NAME, DataType::Boolean, false));
    TrackedTableOracle::single_column_with_activator(predicate_field, predicate_oracle, None)
}

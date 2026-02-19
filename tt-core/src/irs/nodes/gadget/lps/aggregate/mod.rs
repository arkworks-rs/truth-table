use std::sync::Arc;

use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{DataType, Field};
use datafusion_expr::Aggregate;
use indexmap::IndexMap;

use crate::irs::nodes::gadget::utils::{bool, supp};
use crate::irs::nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps};
use crate::irs::payloads::PayloadStructure;
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

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        if self.has_groups() {
            vec![
                self.supp_gadget.as_ref().unwrap().clone(),
                self.bool_gadget.as_ref().unwrap().clone(),
            ]
        } else {
            vec![]
        }
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
        if !self.has_groups() {
            return Ok(());
        }
        let gadget_payload = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => panic!("Expected gadget payload for aggregate node"),
        };

        let (input_table, output_table) = match (
            gadget_payload.get(INPUT_LABEL),
            gadget_payload.get(OUTPUT_LABEL),
        ) {
            (Some(input), Some(output)) => (input.clone(), output.clone()),
            _ => panic!("Expected aggregate input and output tables"),
        };

        let mut supp_payload =
            match virtualized_ir.payload_for_node(&self.supp_gadget.as_ref().unwrap().id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };

        supp_payload.insert(supp::ORIG_LABEL.to_string(), input_table.clone());
        // println!("Input: {}", input_table.pretty_string());
        supp_payload.insert(supp::SUPER_LABEL.to_string(), output_table.clone());
        // println!("Output: {}", output_table.pretty_string());
        virtualized_ir.set_payload_for_node(
            self.supp_gadget.as_ref().unwrap().id(),
            Some(PayloadStructure::GadgetPayload(supp_payload)),
        );

        let bool_table = bool_table_from_output_prover(&output_table);
        let mut bool_payload =
            match virtualized_ir.payload_for_node(&self.bool_gadget.as_ref().unwrap().id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
        bool_payload.insert(bool::TABLE_LABEL.to_string(), bool_table);
        virtualized_ir.set_payload_for_node(
            self.bool_gadget.as_ref().unwrap().id(),
            Some(PayloadStructure::GadgetPayload(bool_payload)),
        );
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
        if !self.has_groups() {
            return Ok(());
        }
        let gadget_payload = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => panic!("Expected gadget payload for aggregate node"),
        };

        let (input_table, output_table) = match (
            gadget_payload.get(INPUT_LABEL),
            gadget_payload.get(OUTPUT_LABEL),
        ) {
            (Some(input), Some(output)) => (input.clone(), output.clone()),
            _ => panic!("Expected aggregate input and output tables"),
        };

        let mut supp_payload =
            match virtualized_ir.payload_for_node(&self.supp_gadget.as_ref().unwrap().id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };

        supp_payload.insert(supp::ORIG_LABEL.to_string(), input_table);
        supp_payload.insert(supp::SUPER_LABEL.to_string(), output_table.clone());

        virtualized_ir.set_payload_for_node(
            self.supp_gadget.as_ref().unwrap().id(),
            Some(PayloadStructure::GadgetPayload(supp_payload)),
        );

        let bool_table = bool_table_from_output_verifier(&output_table);
        let mut bool_payload =
            match virtualized_ir.payload_for_node(&self.bool_gadget.as_ref().unwrap().id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
        bool_payload.insert(bool::TABLE_LABEL.to_string(), bool_table);
        virtualized_ir.set_payload_for_node(
            self.bool_gadget.as_ref().unwrap().id(),
            Some(PayloadStructure::GadgetPayload(bool_payload)),
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
        // TODO: implement gadget proof
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

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}
impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(aggregate: Aggregate) -> Self {
        let (supp_gadget, bool_gadget) = if aggregate.group_expr.is_empty() {
            (None, None)
        } else {
            (
                Some(Arc::new(Node::<B>::Gadget(Arc::new(
                    crate::irs::nodes::gadget::utils::supp::GadgetNode::new(),
                )))),
                Some(Arc::new(Node::<B>::Gadget(Arc::new(
                    crate::irs::nodes::gadget::utils::bool::GadgetNode::<B>::new(),
                )))),
            )
        };
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

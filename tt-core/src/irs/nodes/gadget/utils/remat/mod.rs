use std::sync::Arc;

use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{
            IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps,
            gadget::utils::{bool, perm},
        },
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};
pub const INPUT_LABEL: &str = "__input__";
pub const OUTPUT_LABEL: &str = "__output__";
#[allow(unused)]
pub struct GadgetNode<B: SnarkBackend> {
    contigous: bool,
    bool_check_gadget: Arc<Node<B>>,
    perm_check_gadget: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Rematerialization".to_string()
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
            .unwrap_or_else(|| panic!("Rematerialization gadget missing {}", INPUT_LABEL));
        let output = payload
            .get(OUTPUT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Rematerialization gadget missing {}", OUTPUT_LABEL));

        populate_bool_payload_prover(&self.bool_check_gadget, &output, virtualized_ir)?;
        populate_perm_payloads_prover(&self.perm_check_gadget, &input, &output, virtualized_ir)?;
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::prover::irs::OutputPlannedIr<B>,
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
            .unwrap_or_else(|| panic!("Rematerialization gadget missing {}", INPUT_LABEL));
        let output = payload
            .get(OUTPUT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Rematerialization gadget missing {}", OUTPUT_LABEL));

        populate_bool_payload_verifier(&self.bool_check_gadget, &output, virtualized_ir)?;
        populate_perm_payloads_verifier(&self.perm_check_gadget, &input, &output, virtualized_ir)?;
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::verifier::irs::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
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

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::verifier_hint::VerifierHint> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(contigous: bool) -> Self
    where
        Self: Sized,
    {
        let bool_check_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::bool::GadgetNode::new(),
        )));

        let perm_check_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::perm::GadgetNode::new(),
        )));
        Self {
            contigous,
            bool_check_gadget,
            perm_check_gadget,
        }
    }
}

fn bool_table_from_output_prover<B: SnarkBackend>(output: &TrackedTable<B>) -> TrackedTable<B> {
    let activator = output
        .activator_tracked_poly()
        .expect("Rematerialization output should carry an activator column");
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
        .expect("Rematerialization output should carry an activator column");
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
    let mut perm_payload = match virtualized_ir.payload_for_node(&perm_gadget.id()) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    perm_payload.insert(perm::LEFT_LABEL.to_string(), input.clone());
    perm_payload.insert(perm::RIGHT_LABEL.to_string(), output.clone());
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
    let mut perm_payload = match virtualized_ir.payload_for_node(&perm_gadget.id()) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    perm_payload.insert(perm::LEFT_LABEL.to_string(), input.clone());
    perm_payload.insert(perm::RIGHT_LABEL.to_string(), output.clone());
    virtualized_ir.set_payload_for_node(
        perm_gadget.id(),
        Some(PayloadStructure::GadgetPayload(perm_payload)),
    );
    Ok(())
}

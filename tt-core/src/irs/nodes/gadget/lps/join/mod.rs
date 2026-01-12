use std::sync::Arc;

use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use indexmap::IndexMap;

use crate::irs::{
    nodes::{
        gadget::utils::bool, IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps,
    },
    payloads::PayloadStructure,
};
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;

pub const LEFT_LABEL: &str = "__LEFT__";
pub const RIGHT_LABEL: &str = "__RIGHT__";
pub const OUTPUT_LABEL: &str = "__OUTPUT__";

pub struct GadgetNode<B: SnarkBackend> {
    bool_gadget: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Join".to_string()
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
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.bool_gadget.clone()]
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
        let Some(output) = payload.get(OUTPUT_LABEL) else {
            return Ok(());
        };
        let bool_table = bool_table_from_output_prover(output);
        let mut bool_payload = match virtualized_ir.payload_for_node(&self.bool_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        bool_payload.insert(bool::TABLE_LABEL.to_string(), bool_table);
        virtualized_ir.set_payload_for_node(
            self.bool_gadget.id(),
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
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };
        let Some(output) = payload.get(OUTPUT_LABEL) else {
            return Ok(());
        };
        let bool_table = bool_table_from_output_verifier(output);
        let mut bool_payload = match virtualized_ir.payload_for_node(&self.bool_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        bool_payload.insert(bool::TABLE_LABEL.to_string(), bool_table);
        virtualized_ir.set_payload_for_node(
            self.bool_gadget.id(),
            Some(PayloadStructure::GadgetPayload(bool_payload)),
        );
        Ok(())
    }
}

fn bool_table_from_output_prover<B: SnarkBackend>(output: &TrackedTable<B>) -> TrackedTable<B> {
    let activator = output
        .activator_tracked_poly()
        .expect("Join output should carry an activator column");
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
        .expect("Join output should carry an activator column");
    let field = Arc::new(Field::new("data", DataType::Boolean, false));
    let mut tracked_oracles = IndexMap::new();
    tracked_oracles.insert(field.clone(), activator);
    let schema = Some(Schema::new(vec![field.as_ref().clone()]));
    TrackedTableOracle::new(schema, tracked_oracles, output.log_size())
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

impl<B: SnarkBackend> Default for GadgetNode<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new() -> Self {
        let bool_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::bool::GadgetNode::new(),
        )));
        Self { bool_gadget }
    }
}

use std::sync::Arc;

use ark_piop::{SnarkBackend, prover::ArgProver, verifier::ArgVerifier};

use indexmap::IndexMap;

use crate::{
    irs::nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};
mod hints;
mod wiring;
use wiring::{
    io_rlc_prover, io_rlc_verifier, io_tables_prover, io_tables_verifier,
    populate_lookup_payload_prover, populate_lookup_payload_verifier,
    populate_nodup_payload_prover, populate_nodup_payload_verifier,
    populate_self_rlc_payload_prover, populate_self_rlc_payload_verifier,
};

pub const ORIG_LABEL: &str = "__orig__";
pub const ORIG_RLC_LABEL: &str = "__orig-rlc__";
pub const SUPER_LABEL: &str = "__super__";
pub const SUPER_RLC_LABEL: &str = "__super-rlc__";

pub struct GadgetNode<B: SnarkBackend> {
    lookup: Arc<Node<B>>,
    nodup: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Support".to_string()
    }

    fn display(&self) -> String {
        self.name()
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
        // First fetch the original and support hints from the payload.
        let (orig_hint, support_hint) = hints::io_plans(planned_ir, id);
        // Then populate the nodup plans
        hints::populate_nodup(planned_ir, self.nodup.id(), support_hint.clone());
        // Finally populate the lookup plans
        hints::populate_lookup(planned_ir, self.lookup.id(), orig_hint, support_hint);
        Ok(())
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        vec![self.lookup.clone(), self.nodup.clone()]
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
        // First fetch the original and support hints from the payload.
        let (payload, orig_table, super_table) = io_tables_prover(virtualized_ir, id);
        // Then compute the RLCs for both tables.
        let (orig_rlc, super_rlc) = io_rlc_prover(&orig_table, &super_table);
        // Then populate the nodup payloads
        populate_nodup_payload_prover(virtualized_ir, self.nodup.id(), super_table.clone())?;
        // Then populate the lookup payloads
        populate_lookup_payload_prover(
            virtualized_ir,
            self.lookup.id(),
            orig_rlc.clone(),
            super_rlc.clone(),
        )?;
        // Finally, populate the self RLC payload
        populate_self_rlc_payload_prover(id, virtualized_ir, payload, orig_rlc, super_rlc)?;
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
        // First fetch the original and support hints from the payload.
        let (payload, orig_table, super_table) = io_tables_verifier(virtualized_ir, id);
        // Then compute the RLCs for both tables.
        let (orig_rlc, super_rlc) = io_rlc_verifier(&orig_table, &super_table);
        // Then populate the nodup payloads
        populate_nodup_payload_verifier(virtualized_ir, self.nodup.id(), super_table.clone())?;
        // Then populate the lookup payloads
        populate_lookup_payload_verifier(
            virtualized_ir,
            self.lookup.id(),
            orig_rlc.clone(),
            super_rlc.clone(),
        )?;
        // Finally, populate the self RLC payload
        populate_self_rlc_payload_verifier(id, virtualized_ir, payload, orig_rlc, super_rlc)?;

        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        _prover: &mut ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn verify(
        &self,
        _verifier: &mut ArgVerifier<B>,
        _gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> Default for GadgetNode<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new() -> Self {
        let lookup = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::lookup::GadgetNode::new(),
        )));
        let nodup = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::nodup::GadgetNode::default(),
        )));
        Self { lookup, nodup }
    }
}

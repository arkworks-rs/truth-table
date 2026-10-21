use std::sync::Arc;

use ark_piop::{SnarkBackend, prover::ArgProver, verifier::ArgVerifier};

use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps, utils::lookup},
        payloads::PayloadStructure,
    },
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

    fn children(&self) -> Vec<Arc<Node<B>>> {
        vec![self.lookup.clone(), self.nodup.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let (orig_hint, support_hint) = hints::io_plans(planned_ir, id);
        hints::populate_nodup(planned_ir, self.nodup.id(), support_hint.clone());
        hints::populate_lookup(planned_ir, self.lookup.id(), orig_hint, support_hint);
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
        let (payload, orig_table, super_table) = io_tables_prover(virtualized_ir, id);
        let (orig_rlc, super_rlc) = io_rlc_prover(&orig_table, &super_table);
        populate_nodup_payload_prover(virtualized_ir, self.nodup.id(), super_table.clone())?;
        populate_lookup_payload_prover(
            virtualized_ir,
            self.lookup.id(),
            orig_rlc.clone(),
            super_rlc.clone(),
        )?;
        populate_self_rlc_payload_prover(id, virtualized_ir, payload, orig_rlc, super_rlc)?;
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let (orig_hint, support_hint) = hints::io_plans(planned_ir, id);
        hints::populate_nodup(planned_ir, self.nodup.id(), support_hint.clone());
        hints::populate_lookup(planned_ir, self.lookup.id(), orig_hint, support_hint);
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
        let (payload, orig_table, super_table) = io_tables_verifier(virtualized_ir, id);
        let (orig_rlc, super_rlc) = io_rlc_verifier(&orig_table, &super_table);
        populate_nodup_payload_verifier(virtualized_ir, self.nodup.id(), super_table.clone())?;
        populate_lookup_payload_verifier(
            virtualized_ir,
            self.lookup.id(),
            orig_rlc.clone(),
            super_rlc.clone(),
        )?;
        populate_self_rlc_payload_verifier(id, virtualized_ir, payload, orig_rlc, super_rlc)?;

        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    /// Paper Suppcheck, step 3: no active row of the super table has
    /// multiplicity 0, so it holds no row the original table lacks. The
    /// challenge `c` lifts inactive rows off zero: `m + c·(1 − a)`.
    fn prove(
        &self,
        prover: &mut ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let activator = payload_table(gadget_ready_ir.payload_for_node(&id), SUPER_LABEL)
            .activator_tracked_poly()
            .expect("Support super table must carry an activator");
        let multiplicities = payload_table(
            gadget_ready_ir.payload_for_node(&self.lookup.id()),
            lookup::SUPER_MULTIPLICITIES_LABEL,
        );
        let m = multiplicities
            .tracked_col_by_ind(multiplicities.data_tracked_polys_indices()[0])
            .data_tracked_poly();
        let c = prover.get_and_append_challenge(b"supp_nonzero")?;
        let lifted = &m + &activator.mul_scalar_poly(-c).add_scalar_poly(c);
        prover.add_mv_nozerocheck_claim(lifted.id())
    }

    fn verify(
        &self,
        verifier: &mut ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let activator = payload_table(gadget_ready_ir.payload_for_node(&id), SUPER_LABEL)
            .activator_tracked_poly()
            .expect("Support super table must carry an activator");
        let multiplicities = payload_table(
            gadget_ready_ir.payload_for_node(&self.lookup.id()),
            lookup::SUPER_MULTIPLICITIES_LABEL,
        );
        let m = multiplicities
            .tracked_col_oracle_by_ind(multiplicities.data_tracked_oracles_indices()[0])
            .data_tracked_oracle();
        let c = verifier.get_and_append_challenge(b"supp_nonzero")?;
        let lifted = &m + &activator.mul_scalar_oracle(-c).add_scalar_oracle(c);
        verifier.add_mv_nozerocheck_claim(lifted.id());
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

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

fn payload_table<'a, T>(payload: Option<&'a PayloadStructure<T>>, label: &str) -> &'a T {
    match payload {
        Some(PayloadStructure::GadgetPayload(map)) => map
            .get(label)
            .unwrap_or_else(|| panic!("Support gadget missing {label}")),
        _ => panic!("Support gadget missing its payload"),
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
            crate::irs::nodes::utils::lookup::GadgetNode::new(),
        )));
        let nodup = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::utils::nodup::GadgetNode::default(),
        )));
        Self { lookup, nodup }
    }
}

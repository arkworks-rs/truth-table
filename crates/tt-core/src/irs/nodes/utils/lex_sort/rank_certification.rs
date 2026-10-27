//! The Rank Certification Check ([`piop::rank_certification`]) as a gadget.
//! No query plans it: a table scan's rank is the data owner's, like its
//! characters, so a query has no rank to certify.
//!
//! Payload:
//! - [`STRINGS_LABEL`]: data columns the hash slots, the length and the rank,
//!   in that order, under the column's activator `a`.
//! - [`CHARS_LABEL`]: data columns `orig-ind`, `int-ind` and `char`, in that
//!   order, under `char-act`; `orig-ind` is the row of the strings table.
//!
//! [`piop::rank_certification`]: super::piop::rank_certification

use ark_piop::{SnarkBackend, errors::SnarkResult, prover::ArgProver, verifier::ArgVerifier};
use indexmap::IndexMap;

use super::{
    data_oracles, data_polys,
    piop::{
        character_projection::Characters,
        rank_certification::{self, RankedStrings},
    },
};
use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, NodeId, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub const STRINGS_LABEL: &str = "__ranked_strings__";
pub const CHARS_LABEL: &str = "__chars__";

pub struct GadgetNode<B: SnarkBackend>(std::marker::PhantomData<B>);

impl<B: SnarkBackend> Default for GadgetNode<B> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

/// `[hash slots…, length, rank]` under `activator`, and the character
/// table's `[orig-ind, int-ind, char]` under its activator.
pub(super) fn columns<P: Clone>(
    mut strings: Vec<P>,
    activator: P,
    chars: Vec<P>,
    char_activator: P,
) -> (RankedStrings<P>, Characters<P>) {
    assert!(
        strings.len() >= 3,
        "RankCertificationCheck: the strings table holds hash slots, length and rank"
    );
    let rank = strings.pop().expect("a rank column");
    let length = strings.pop().expect("a length column");
    let [orig_ind, int_ind, chars]: [P; 3] = chars
        .try_into()
        .ok()
        .expect("RankCertificationCheck: the character table holds orig-ind, int-ind and char");
    (
        RankedStrings {
            hash: strings,
            length,
            rank,
            activator,
        },
        Characters {
            orig_ind,
            int_ind,
            chars,
            activator: char_activator,
        },
    )
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "RankCertificationCheck".to_string()
    }

    fn display(&self) -> String {
        crate::irs::nodes::display_with_inputs(&self.name(), &self.children())
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _prover: &mut ArgProver<B>,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _verifier: &mut ArgVerifier<B>,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("RankCertificationCheck: missing gadget payload");
        };
        let strings = &payload[STRINGS_LABEL];
        let chars = &payload[CHARS_LABEL];
        let (ranked, characters) = columns(
            data_polys(strings),
            strings
                .activator_tracked_poly()
                .expect("RankCertificationCheck: the strings table has an activator"),
            data_polys(chars),
            chars
                .activator_tracked_poly()
                .expect("RankCertificationCheck: the character table has an activator"),
        );
        rank_certification::prove(prover, &ranked, &characters, strings.log_size())
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: NodeId,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn verify(
        &self,
        verifier: &mut ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("RankCertificationCheck: missing gadget payload");
        };
        let strings = &payload[STRINGS_LABEL];
        let chars = &payload[CHARS_LABEL];
        let (ranked, characters) = columns(
            data_oracles(strings),
            strings
                .activator_tracked_poly()
                .expect("RankCertificationCheck: the strings table has an activator"),
            data_oracles(chars),
            chars
                .activator_tracked_poly()
                .expect("RankCertificationCheck: the character table has an activator"),
        );
        rank_certification::verify(verifier, &ranked, &characters, strings.log_size())
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

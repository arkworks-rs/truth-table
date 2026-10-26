//! The Lexicographic Sortedness Check ([`piop::sortedness`]) as a gadget, on
//! every adjacent pair of the first `n` rows, for unit tests only: every
//! production caller chains the PIOP inline with other keys or needs `same`.
//!
//! Payload:
//! - [`STRINGS_LABEL`]: data columns `index`, the hash slots and the length,
//!   in that order. The column's activator is `C_{µ,n}`; the table's own
//!   activator is not read.
//! - [`CHARS_LABEL`]: data columns `orig-ind`, `int-ind` and `char`, in that
//!   order, under `char-act`.
//! - [`ACTIVE_ROWS_LABEL`]: the committed scalar `n`.
//!
//! [`piop::sortedness`]: super::piop::sortedness
//! [`ACTIVE_ROWS_LABEL`]: crate::irs::nodes::utils::contig_sort::ACTIVE_ROWS_LABEL

use ark_piop::{SnarkBackend, errors::SnarkResult, prover::ArgProver, verifier::ArgVerifier};
use indexmap::IndexMap;

use super::{
    data_oracles, data_polys,
    piop::{
        Tie,
        character_projection::Characters,
        sortedness::{self, SortedStrings},
    },
};
use crate::{
    irs::{
        nodes::{
            IsGadgetNode, IsNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
            utils::contig_sort::{ACTIVE_ROWS_LABEL, active_rows_prover, active_rows_verifier},
        },
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub const STRINGS_LABEL: &str = "__sorted_strings__";
pub const CHARS_LABEL: &str = "__chars__";

pub struct GadgetNode<B: SnarkBackend> {
    asc: bool,
    _backend: std::marker::PhantomData<B>,
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(asc: bool) -> Self {
        Self {
            asc,
            _backend: std::marker::PhantomData,
        }
    }
}

/// `[index, hash slots…, length]` as a sorted column, and the character
/// table's `[orig-ind, int-ind, char]` under its activator.
pub(super) fn columns<P: Clone>(
    mut strings: Vec<P>,
    chars: Vec<P>,
    char_activator: P,
) -> (SortedStrings<P>, Characters<P>) {
    assert!(
        strings.len() >= 3,
        "LexSortednessCheck: the strings table holds index, hash slots and length"
    );
    let length = strings.pop().expect("a length column");
    let index = strings.remove(0);
    let [orig_ind, int_ind, chars]: [P; 3] = chars
        .try_into()
        .ok()
        .expect("LexSortednessCheck: the character table holds orig-ind, int-ind and char");
    (
        SortedStrings {
            index,
            hash: strings,
            length,
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
        "LexSortednessCheck".to_string()
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
            panic!("LexSortednessCheck: missing gadget payload");
        };
        let strings = &payload[STRINGS_LABEL];
        let chars = &payload[CHARS_LABEL];
        let n = active_rows_prover(&payload[ACTIVE_ROWS_LABEL])?;
        let log_size = strings.log_size();
        let (strings, chars) = columns(
            data_polys(strings),
            data_polys(chars),
            chars
                .activator_tracked_poly()
                .expect("LexSortednessCheck: the character table has an activator"),
        );
        let tie = Tie::mask(prover, log_size, n)?;
        sortedness::prove(prover, &strings, &chars, tie, &[], self.asc)?;
        Ok(())
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
            panic!("LexSortednessCheck: missing gadget payload");
        };
        let strings = &payload[STRINGS_LABEL];
        let chars = &payload[CHARS_LABEL];
        let n = active_rows_verifier(&payload[ACTIVE_ROWS_LABEL])?;
        let log_size = strings.log_size();
        let (strings, chars) = columns(
            data_oracles(strings),
            data_oracles(chars),
            chars
                .activator_tracked_poly()
                .expect("LexSortednessCheck: the character table has an activator"),
        );
        let tie = Tie::mask_oracle(verifier, log_size, n)?;
        sortedness::verify(verifier, &strings, &chars, tie, &[], self.asc)?;
        Ok(())
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

//! A composite gadget node for the Rotation Check (paper Appendix B.10).
//!
//! Given a single-column table `left` and a single-column table `right`
//! (both over the same domain of `2^log_size` rows), the gadget proves
//! that `right` is the cyclic rotation of `left` by `shift` positions
//! in the specified direction:
//!
//! - [`Direction::Right`] with shift `s`:  `right[i] = left[(i - s) mod n]`
//!   — the values of `left` are pushed `s` positions to the right.
//! - [`Direction::Left`] with shift `s`:   `right[i] = left[(i + s) mod n]`
//!   — the values of `left` are pushed `s` positions to the left.
//!
//! Payload structure:
//! - [`LEFT_LABEL`] — single-column input table.
//! - [`RIGHT_LABEL`] — single-column rotated table.
//!
//! Decomposition. The check reduces to a [`PrescribedPermutation`] on
//! the shift permutation `π` defined by
//!
//! ```text
//! π[i] = (i - s) mod n     (Direction::Right)
//! π[i] = (i + s) mod n     (Direction::Left)
//! ```
//!
//! since `PrescribedPermutation`'s core relation is `left[i] = right[π[i]]`,
//! and the two rotation-direction formulations above make that identity
//! hold.
use std::sync::Arc;

use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_piop::{
    SnarkBackend, prover::structs::polynomial::get_or_insert_shift_poly,
    verifier::structs::oracle::get_or_insert_shift_oracle,
};
use datafusion::arrow::datatypes::{DataType, Field};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{
            IsGadgetNode, IsNode, Node, NodeId, ProverNodeOps, VerifierNodeOps, utils::prescr_perm,
        },
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub const LEFT_LABEL: &str = "__left__";
pub const RIGHT_LABEL: &str = "__right__";

/// Rotation direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// `right[i] = left[(i - shift) mod n]` — values move right by `shift`.
    Right,
    /// `right[i] = left[(i + shift) mod n]` — values move left by `shift`.
    Left,
}

impl Direction {
    /// Argument to [`get_or_insert_shift_poly`]/[`get_or_insert_shift_oracle`]
    /// that matches this direction.
    ///
    /// The helpers build a shift permutation `π` that combines with
    /// `PrescribedPermutation`'s core relation `left[i] = right[π[i]]`
    /// as follows:
    /// - `shift=s, right=true`  ⇒  `π[i] = (i - s) mod n`  ⇒  `right[j] = left[(j + s) mod n]`  (values shift LEFT)
    /// - `shift=s, right=false` ⇒  `π[i] = (i + s) mod n`  ⇒  `right[j] = left[(j - s) mod n]`  (values shift RIGHT)
    ///
    /// So `Direction::Right` (values push right) picks the `right=false` helper.
    fn shift_is_right(self) -> bool {
        matches!(self, Direction::Left)
    }
}

/// Composite gadget node for the Rotation relation.
pub struct GadgetNode<B: SnarkBackend> {
    shift: usize,
    direction: Direction,
    prescr_perm: Arc<Node<B>>,
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(shift: usize, direction: Direction) -> Self {
        let prescr_perm = Arc::new(Node::<B>::Gadget(Arc::new(prescr_perm::GadgetNode::new())));
        Self {
            shift,
            direction,
            prescr_perm,
        }
    }

    pub fn shift(&self) -> usize {
        self.shift
    }

    pub fn direction(&self) -> Direction {
        self.direction
    }
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "RotationCheck".to_string()
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

    fn children(&self) -> Vec<Arc<Node<B>>> {
        vec![self.prescr_perm.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let (left, right) = extract_prover_inputs(virtualized_ir, id);
        let perm_table = build_perm_table_prover::<B>(prover, left, self.shift, self.direction);

        let mut perm_payload = match virtualized_ir.payload_for_node(&self.prescr_perm.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        perm_payload.insert(prescr_perm::LEFT_LABEL.to_string(), left.clone());
        perm_payload.insert(prescr_perm::RIGHT_LABEL.to_string(), right.clone());
        perm_payload.insert(prescr_perm::PERM_LABEL.to_string(), perm_table);
        virtualized_ir.set_payload_for_node(
            self.prescr_perm.id(),
            Some(PayloadStructure::GadgetPayload(perm_payload)),
        );
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let (left, right) = extract_verifier_inputs(virtualized_ir, id);
        let perm_table = build_perm_table_verifier::<B>(verifier, left, self.shift, self.direction);

        let mut perm_payload = match virtualized_ir.payload_for_node(&self.prescr_perm.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        perm_payload.insert(prescr_perm::LEFT_LABEL.to_string(), left.clone());
        perm_payload.insert(prescr_perm::RIGHT_LABEL.to_string(), right.clone());
        perm_payload.insert(prescr_perm::PERM_LABEL.to_string(), perm_table);
        virtualized_ir.set_payload_for_node(
            self.prescr_perm.id(),
            Some(PayloadStructure::GadgetPayload(perm_payload)),
        );
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Delegated: PrescribedPermutation already runs an honest
        // permutation check against the shift permutation we handed it.
        Ok(())
    }

    fn verify(
        &self,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        _id: NodeId,
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

fn extract_prover_inputs<B: SnarkBackend>(
    ir: &GadgetReadyIr<B>,
    id: NodeId,
) -> (&TrackedTable<B>, &TrackedTable<B>) {
    let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
        panic!("RotationCheck: missing gadget payload");
    };
    let left = payload
        .get(LEFT_LABEL)
        .unwrap_or_else(|| panic!("RotationCheck: missing {}", LEFT_LABEL));
    let right = payload
        .get(RIGHT_LABEL)
        .unwrap_or_else(|| panic!("RotationCheck: missing {}", RIGHT_LABEL));
    (left, right)
}

fn extract_verifier_inputs<B: SnarkBackend>(
    ir: &VerifierGadgetReadyIr<B>,
    id: NodeId,
) -> (&TrackedTableOracle<B>, &TrackedTableOracle<B>) {
    let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
        panic!("RotationCheck: missing gadget payload");
    };
    let left = payload
        .get(LEFT_LABEL)
        .unwrap_or_else(|| panic!("RotationCheck: missing {}", LEFT_LABEL));
    let right = payload
        .get(RIGHT_LABEL)
        .unwrap_or_else(|| panic!("RotationCheck: missing {}", RIGHT_LABEL));
    (left, right)
}

fn build_perm_table_prover<B: SnarkBackend>(
    prover: &mut ark_piop::prover::ArgProver<B>,
    left: &TrackedTable<B>,
    shift: usize,
    direction: Direction,
) -> TrackedTable<B> {
    let log_size = left.log_size();
    let perm_poly = get_or_insert_shift_poly(prover, log_size, shift, direction.shift_is_right());
    let perm_field = Arc::new(Field::new(prescr_perm::PERM_LABEL, DataType::UInt64, false));
    TrackedTable::single_column_with_activator(perm_field, perm_poly, None)
}

fn build_perm_table_verifier<B: SnarkBackend>(
    verifier: &mut ark_piop::verifier::ArgVerifier<B>,
    left: &TrackedTableOracle<B>,
    shift: usize,
    direction: Direction,
) -> TrackedTableOracle<B> {
    let log_size = left.log_size();
    let perm_oracle =
        get_or_insert_shift_oracle(verifier, log_size, shift, direction.shift_is_right());
    let perm_field = Arc::new(Field::new(prescr_perm::PERM_LABEL, DataType::UInt64, false));
    TrackedTableOracle::single_column_with_activator(perm_field, perm_oracle, None)
}

#[cfg(test)]
mod tests;

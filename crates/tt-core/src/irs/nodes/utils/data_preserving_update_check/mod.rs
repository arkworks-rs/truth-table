//! Data-Preserving Update Check (paper §5.2.1, PIOP 3).
//!
//! Proves that a fresh activator pair `(char-act, a)` is a data-preserving
//! update of the existing columns `(orig-ind, ind, l)`:
//!
//! 1. `char-act[c] ∈ {0, 1}` for every char slot,
//! 2. `a[i] ∈ {0, 1}` for every string slot,
//! 3. `Σ_{j : orig-ind[j] = i} char-act[j] = a[i] · l[i]` for every string `i`.
//!
//! Every constraint is in a child: two `BoolCheck`s, and an
//! `ActivatorConsistencyCheck` on `(orig-ind, char-act, l, a)`, whose keyed
//! sumcheck ties the two activators together through the length column.
use crate::irs::nodes::utils::bool_field;
use std::marker::PhantomData;
use std::sync::Arc;

use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_piop::{SnarkBackend, errors::SnarkResult};
use datafusion::arrow::datatypes::Schema;
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{
            IsGadgetNode, IsNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
            utils::{activator_consistency_check, bool as bool_check},
        },
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

/// Char-level table `{ orig-ind }` under `char-act`.
pub const LHS_LABEL: &str = "__lhs__";
/// String-level table `{ ind, l }`, in that order, under `a`.
pub const RHS_LABEL: &str = "__rhs__";

pub struct GadgetNode<B: SnarkBackend> {
    bool_char_act: Arc<Node<B>>,
    bool_a: Arc<Node<B>>,
    activator_consistency: Arc<Node<B>>,
    _phantom: PhantomData<B>,
}

impl<B: SnarkBackend> Default for GadgetNode<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new() -> Self {
        let bool_char_act = Arc::new(Node::<B>::Gadget(Arc::new(bool_check::GadgetNode::new())));
        let bool_a = Arc::new(Node::<B>::Gadget(Arc::new(bool_check::GadgetNode::new())));
        let activator_consistency = Arc::new(Node::<B>::Gadget(Arc::new(
            activator_consistency_check::GadgetNode::new(),
        )));
        Self {
            bool_char_act,
            bool_a,
            activator_consistency,
            _phantom: PhantomData,
        }
    }
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "DataPreservingUpdateCheck".to_string()
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
        vec![
            self.bool_char_act.clone(),
            self.bool_a.clone(),
            self.activator_consistency.clone(),
        ]
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
        id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = virtualized_ir.payload_for_node(&id)
        else {
            panic!("DataPreservingUpdateCheck: missing gadget payload");
        };
        let lhs = payload.get(LHS_LABEL).expect("missing LHS").clone();
        let rhs = payload.get(RHS_LABEL).expect("missing RHS").clone();

        let char_act = lhs
            .activator_tracked_poly()
            .expect("LHS must carry activator char-act");
        let a = rhs
            .activator_tracked_poly()
            .expect("RHS must carry activator a");

        set_bool_payload_prover(&self.bool_char_act, char_act, virtualized_ir);
        set_bool_payload_prover(&self.bool_a, a, virtualized_ir);

        // ActivatorConsistencyCheck takes the same (LHS, RHS) tables.
        let mut ac_payload = IndexMap::new();
        ac_payload.insert(activator_consistency_check::LHS_LABEL.to_string(), lhs);
        ac_payload.insert(activator_consistency_check::RHS_LABEL.to_string(), rhs);
        virtualized_ir.set_payload_for_node(
            self.activator_consistency.id(),
            Some(PayloadStructure::GadgetPayload(ac_payload)),
        );
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
        id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = virtualized_ir.payload_for_node(&id)
        else {
            panic!("DataPreservingUpdateCheck: missing gadget payload");
        };
        let lhs = payload.get(LHS_LABEL).expect("missing LHS").clone();
        let rhs = payload.get(RHS_LABEL).expect("missing RHS").clone();

        let char_act = lhs
            .activator_tracked_poly()
            .expect("LHS must carry activator char-act");
        let a = rhs
            .activator_tracked_poly()
            .expect("RHS must carry activator a");

        set_bool_payload_verifier(&self.bool_char_act, char_act, virtualized_ir);
        set_bool_payload_verifier(&self.bool_a, a, virtualized_ir);

        let mut ac_payload = IndexMap::new();
        ac_payload.insert(activator_consistency_check::LHS_LABEL.to_string(), lhs);
        ac_payload.insert(activator_consistency_check::RHS_LABEL.to_string(), rhs);
        virtualized_ir.set_payload_for_node(
            self.activator_consistency.id(),
            Some(PayloadStructure::GadgetPayload(ac_payload)),
        );
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
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: NodeId,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: NodeId,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn verify(
        &self,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        _id: NodeId,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

fn set_bool_payload_prover<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    data: ark_piop::prover::structs::polynomial::TrackedPoly<B>,
    ir: &mut GadgetReadyIr<B>,
) {
    let mut polys = IndexMap::new();
    polys.insert(bool_field(), data.clone());
    let schema = Schema::new(vec![bool_field().as_ref().clone()]);
    let table = TrackedTable::new(Some(schema), polys, data.log_size());
    let mut payload = IndexMap::new();
    payload.insert(bool_check::TABLE_LABEL.to_string(), table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

fn set_bool_payload_verifier<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    data: ark_piop::verifier::structs::oracle::TrackedOracle<B>,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let mut oracles = IndexMap::new();
    oracles.insert(bool_field(), data.clone());
    let schema = Schema::new(vec![bool_field().as_ref().clone()]);
    let table = TrackedTableOracle::new(Some(schema), oracles, data.log_size());
    let mut payload = IndexMap::new();
    payload.insert(bool_check::TABLE_LABEL.to_string(), table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

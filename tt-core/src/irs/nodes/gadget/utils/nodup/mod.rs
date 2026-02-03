use std::sync::Arc;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};
use arithmetic::ROW_ID_COL_NAME;
use ark_piop::{SnarkBackend, prover::ArgProver, verifier::ArgVerifier};
use indexmap::IndexMap;

pub const INPUT_LABEL: &str = "_input_";
pub const LEX_SORTED_LABEL: &str = "_lex_sorted_";

mod bezout;
mod binary_check;
mod defragg;
mod hints;
mod keyed_sumcheck;
mod perm_check;
mod rematerialize_check;

pub enum Mode {
    BezoutBased,
    SortBased,
}
pub enum Gadgets<B: SnarkBackend> {
    BezoutNoDup,
    SortNoDup(SortNoDupGadgets<B>),
}

pub struct SortNoDupGadgets<B: SnarkBackend>(Arc<Node<B>>);

pub struct GadgetNode<B: SnarkBackend> {
    gadgets: Gadgets<B>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "NoDup".to_string()
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
        //////////////////////////////////////////////////////////////////
        // First populate the current node with the lexicographically sorted hint
        let Gadgets::SortNoDup(_) = &self.gadgets else {
            return Ok(());
        };
        let Some(PayloadStructure::GadgetPayload(mut self_payload)) =
            planned_ir.payload_for_node(&id).cloned()
        else {
            panic!("No gadget payload found for node {:?}", id);
        };
        let Some(input_hint) = self_payload.get(INPUT_LABEL).cloned() else {
            panic!("No input hint found for NoDup gadget at node {:?}", id);
        };
        let lex_sorted_df = hints::lex_sort_contiguous(input_hint.data_frame().clone())
            .expect("NoDup lex sort should succeed");
        let should_materialize = lex_sorted_df
            .schema()
            .fields()
            .iter()
            .map(|field| (field.clone(), field.name() != ROW_ID_COL_NAME))
            .collect();
        let lex_sorted_hint =
            crate::irs::nodes::hints::HintDF::new(lex_sorted_df, should_materialize);
        self_payload.insert(LEX_SORTED_LABEL.to_string(), lex_sorted_hint.clone());

        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(self_payload)));
        ///////////////////////////////////////////////////////////////////
        // Next, propagate the virtualized version of the lex sorted hint to the sort gadget node
        let lex_sorted_virtual_hint =
            crate::irs::nodes::hints::HintDF::new_virtual(lex_sorted_hint.data_frame().clone());
        let Gadgets::SortNoDup(gadgets) = &self.gadgets else {
            return Ok(());
        };
        let sort_id = gadgets.0.id();
        let mut sort_payload = match planned_ir.payload_for_node(&sort_id).cloned() {
            Some(PayloadStructure::GadgetPayload(payload)) => payload,
            Some(PayloadStructure::PlanPayload(_)) | None => IndexMap::new(),
        };
        sort_payload.insert(
            crate::irs::nodes::gadget::utils::contig_sort::TABLE_LABEL.to_string(),
            lex_sorted_virtual_hint,
        );
        planned_ir
            .set_payload_for_node(sort_id, Some(PayloadStructure::GadgetPayload(sort_payload)));
        Ok(())
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        match &self.gadgets {
            Gadgets::BezoutNoDup => vec![],
            Gadgets::SortNoDup(g) => vec![g.0.clone()],
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
        let Gadgets::SortNoDup(gadgets) = &self.gadgets else {
            return Ok(());
        };
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            panic!("No gadget payload found for NoDup gadget at node {:?}", id);
        };
        let Some(lex_sorted_hint) = payload.get(LEX_SORTED_LABEL).cloned() else {
            panic!("No lex sorted hint found for NoDup gadget at node {:?}", id);
        };
        let sort_id = gadgets.0.id();
        let mut sort_payload = match virtualized_ir.payload_for_node(&sort_id).cloned() {
            Some(PayloadStructure::GadgetPayload(payload)) => payload,
            Some(PayloadStructure::PlanPayload(_)) | None => IndexMap::new(),
        };
        sort_payload.insert(
            crate::irs::nodes::gadget::utils::contig_sort::TABLE_LABEL.to_string(),
            lex_sorted_hint,
        );
        virtualized_ir
            .set_payload_for_node(sort_id, Some(PayloadStructure::GadgetPayload(sort_payload)));
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
        let Gadgets::SortNoDup(gadgets) = &self.gadgets else {
            return Ok(());
        };
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            panic!("No gadget payload found for NoDup gadget at node {:?}", id);
        };
        let Some(lex_sorted_hint) = payload.get(LEX_SORTED_LABEL).cloned() else {
            panic!("No lex sorted hint found for NoDup gadget at node {:?}", id);
        };
        let sort_id = gadgets.0.id();
        let mut sort_payload = match virtualized_ir.payload_for_node(&sort_id).cloned() {
            Some(PayloadStructure::GadgetPayload(payload)) => payload,
            Some(PayloadStructure::PlanPayload(_)) | None => IndexMap::new(),
        };
        sort_payload.insert(
            crate::irs::nodes::gadget::utils::contig_sort::TABLE_LABEL.to_string(),
            lex_sorted_hint,
        );
        virtualized_ir
            .set_payload_for_node(sort_id, Some(PayloadStructure::GadgetPayload(sort_payload)));
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        match self.gadgets {
            Gadgets::BezoutNoDup => Self::prove_nodup_bezout(prover, gadget_ready_ir, id),
            Gadgets::SortNoDup(_) => Ok(()),
        }
    }

    fn honest_prover_check(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        match self.gadgets {
            Gadgets::BezoutNoDup => Self::honest_check_no_dup_active(prover, gadget_ready_ir, id),
            // SortNoDup is enforced compositionally by its child gadgets
            // (sorting + permutation + keyed constraints), so we intentionally
            // skip the direct active-row duplicate scan in this path.
            Gadgets::SortNoDup(_) => Ok(()),
        }
    }

    fn verify(
        &self,
        verifier: &mut ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        match self.gadgets {
            Gadgets::BezoutNoDup => Self::verify_nodup_bezout(verifier, gadget_ready_ir, id),
            Gadgets::SortNoDup(_) => Ok(()),
        }
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> Default for GadgetNode<B> {
    fn default() -> Self {
        Self::new(Mode::SortBased)
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(mode: Mode) -> Self {
        match mode {
            Mode::BezoutBased => Self {
                gadgets: Gadgets::BezoutNoDup,
            },
            Mode::SortBased => Self {
                gadgets: Gadgets::SortNoDup(SortNoDupGadgets(Arc::new(Node::<B>::Gadget(
                    Arc::new(
                        crate::irs::nodes::gadget::utils::contig_sort::GadgetNode::new_preserve_row_id(
                            crate::irs::nodes::gadget::utils::contig_sort::SortConfig::Uniform(
                                crate::irs::nodes::gadget::utils::contig_sort::UniformConfig {
                                    asc: false,
                                    strict: true,
                                },
                            ),
                        ),
                    ),
                )))),
            },
        }
    }
}

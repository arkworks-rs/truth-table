use std::sync::Arc;

use arithmetic::ROW_ID_COL_NAME;
use ark_piop::{SnarkBackend, prover::ArgProver, verifier::ArgVerifier};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub const INPUT_LABEL: &str = "_input_";
pub const LEX_SORTED_LABEL: &str = "_lex_sorted_";

mod bezout;
mod hints;
#[cfg(test)]
mod tests;

pub enum Gadgets<B: SnarkBackend> {
    BezoutNoDup,
    SortNoDup(SortNoDupGadgets<B>),
}

pub struct SortNoDupGadgets<B: SnarkBackend> {
    pub sort: Arc<Node<B>>,
}

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
        let Gadgets::SortNoDup(_) = &self.gadgets else {
            return Ok(());
        };
        let Some(PayloadStructure::GadgetPayload(mut payload)) = planned_ir
            .payload_for_node(&id)
            .cloned()
        else {
            panic!("No gadget payload found for node {:?}", id);
        };
        let Some(input_hint) = payload.get(INPUT_LABEL).cloned() else {
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
        let lex_sorted_virtual_hint = crate::irs::nodes::hints::HintDF::new(
            lex_sorted_hint.data_frame().clone(),
            lex_sorted_hint
                .data_frame()
                .schema()
                .fields()
                .iter()
                .map(|field| (field.clone(), false))
                .collect(),
        );
        payload.insert(LEX_SORTED_LABEL.to_string(), lex_sorted_hint);
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(payload)));
        let Gadgets::SortNoDup(gadgets) = &self.gadgets else {
            return Ok(());
        };
        let sort_id = gadgets.sort.id();
        let Some(PayloadStructure::GadgetPayload(mut sort_payload)) = planned_ir
            .payload_for_node(&sort_id)
            .cloned()
        else {
            panic!("No gadget payload found for NoDup sort child {:?}", sort_id);
        };
        sort_payload.insert(
            crate::irs::nodes::gadget::utils::contig_sort::TABLE_LABEL.to_string(),
            lex_sorted_virtual_hint,
        );
        planned_ir.set_payload_for_node(
            sort_id,
            Some(PayloadStructure::GadgetPayload(sort_payload)),
        );
        Ok(())
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        match &self.gadgets {
            Gadgets::BezoutNoDup => vec![],
            Gadgets::SortNoDup(g) => vec![g.sort.clone()],
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
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Gadgets::SortNoDup(gadgets) = &self.gadgets else {
            return Ok(());
        };
        let Some(PayloadStructure::GadgetPayload(payload)) = virtualized_ir
            .payload_for_node(&id)
            .cloned()
        else {
            panic!("No gadget payload found for NoDup gadget at node {:?}", id);
        };
        let Some(lex_sorted_hint) = payload.get(LEX_SORTED_LABEL).cloned() else {
            panic!(
                "No lex sorted hint found for NoDup gadget at node {:?}",
                id
            );
        };
        let sort_id = gadgets.sort.id();
        let Some(PayloadStructure::GadgetPayload(mut sort_payload)) = virtualized_ir
            .payload_for_node(&sort_id)
            .cloned()
        else {
            panic!("No gadget payload found for NoDup sort child {:?}", sort_id);
        };
        sort_payload.insert(
            crate::irs::nodes::gadget::utils::contig_sort::TABLE_LABEL.to_string(),
            lex_sorted_hint,
        );
        virtualized_ir.set_payload_for_node(
            sort_id,
            Some(PayloadStructure::GadgetPayload(sort_payload)),
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
        let Gadgets::SortNoDup(gadgets) = &self.gadgets else {
            return Ok(());
        };
        let Some(PayloadStructure::GadgetPayload(payload)) = virtualized_ir
            .payload_for_node(&id)
            .cloned()
        else {
            panic!("No gadget payload found for NoDup gadget at node {:?}", id);
        };
        let Some(lex_sorted_hint) = payload.get(LEX_SORTED_LABEL).cloned() else {
            panic!(
                "No lex sorted hint found for NoDup gadget at node {:?}",
                id
            );
        };
        let sort_id = gadgets.sort.id();
        let Some(PayloadStructure::GadgetPayload(mut sort_payload)) = virtualized_ir
            .payload_for_node(&sort_id)
            .cloned()
        else {
            panic!("No gadget payload found for NoDup sort child {:?}", sort_id);
        };
        sort_payload.insert(
            crate::irs::nodes::gadget::utils::contig_sort::TABLE_LABEL.to_string(),
            lex_sorted_hint,
        );
        virtualized_ir.set_payload_for_node(
            sort_id,
            Some(PayloadStructure::GadgetPayload(sort_payload)),
        );
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
        Self::prove_nodup_bezout(prover, gadget_ready_ir, id)
    }

    fn honest_prover_check(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Self::honest_check_no_dup_active(prover, gadget_ready_ir, id)
    }

    fn verify(
        &self,
        verifier: &mut ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Self::verify_nodup_bezout(verifier, gadget_ready_ir, id)
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> Default for GadgetNode<B> {
    fn default() -> Self {
        Self::new(Gadgets::BezoutNoDup)
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(gadgets: Gadgets<B>) -> Self {
        Self { gadgets }
    }
}

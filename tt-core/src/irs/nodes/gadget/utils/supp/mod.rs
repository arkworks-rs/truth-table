use std::sync::Arc;

use arithmetic::{
    col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_piop::{piop::PIOP, prover::ArgProver, verifier::ArgVerifier, SnarkBackend};
use col_toolbox::supp_check::{SuppCheckPIOP, SuppCheckProverInput, SuppCheckVerifierInput};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub const COL_LABEL: &str = "col";
pub const SUPP_LABEL: &str = "supp";

#[cfg(test)]
mod tests;

pub struct GadgetNode<B: SnarkBackend> {
    phantom: std::marker::PhantomData<B>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Supp".to_string()
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        Vec::new()
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
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
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
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
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
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for Supp gadget node");
        };

        let (Some(col_table), Some(supp_table)) = (
            payload.get(COL_LABEL).cloned(),
            payload.get(SUPP_LABEL).cloned(),
        ) else {
            panic!("Expected col and supp inputs for Supp gadget");
        };

        let col = Self::single_col_from_table(&col_table);
        let supp = Self::single_col_from_table(&supp_table);
        let input = SuppCheckProverInput { col, supp };
        SuppCheckPIOP::<B>::prove(prover, input)?;
        Ok(())
    }

    fn verify(
        &self,
        verifier: &mut ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for Supp gadget node");
        };

        let (Some(col_table), Some(supp_table)) = (
            payload.get(COL_LABEL).cloned(),
            payload.get(SUPP_LABEL).cloned(),
        ) else {
            panic!("Expected col and supp inputs for Supp gadget");
        };

        let col = Self::single_col_from_table_oracle(&col_table);
        let supp = Self::single_col_from_table_oracle(&supp_table);
        let input = SuppCheckVerifierInput { col, supp };
        SuppCheckPIOP::<B>::verify(verifier, input)?;
        Ok(())
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }

    fn single_col_from_table(table: &TrackedTable<B>) -> TrackedCol<B> {
        let data_indices = table.data_tracked_polys_indices();
        debug_assert_eq!(
            data_indices.len(),
            1,
            "Supp gadget expects a single data column per input."
        );
        table.tracked_col_by_ind(data_indices[0])
    }

    fn single_col_from_table_oracle(table: &TrackedTableOracle<B>) -> TrackedColOracle<B> {
        let data_indices = table.data_tracked_oracles_indices();
        debug_assert_eq!(
            data_indices.len(),
            1,
            "Supp gadget expects a single data column per input."
        );
        table.tracked_col_oracle_by_ind(data_indices[0])
    }
}

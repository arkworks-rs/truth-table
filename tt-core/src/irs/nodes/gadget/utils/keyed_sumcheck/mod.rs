use std::sync::Arc;

use arithmetic::{
    col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_piop::{SnarkBackend, piop::PIOP, prover::ArgProver, verifier::ArgVerifier};
use col_toolbox::keyed_sumcheck::{
    KeyedSumcheck, KeyedSumcheckProverInput, KeyedSumcheckVerifierInput,
};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub const FXS_LABEL: &str = "__fxs__";
pub const GXS_LABEL: &str = "__gxs__";
pub const MFXS_LABEL: &str = "__mfxs__";
pub const MGXS_LABEL: &str = "__mgxs__";
#[cfg(test)]
mod tests;

pub struct GadgetNode<B: SnarkBackend> {
    phantom: std::marker::PhantomData<B>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Keyed-Sumcheck".to_string()
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
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
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
            panic!("Expected gadget payload for Keyed-Sumcheck gadget node");
        };

        let (Some(fxs_table), Some(gxs_table)) = (
            payload.get(FXS_LABEL).cloned(),
            payload.get(GXS_LABEL).cloned(),
        ) else {
            panic!("Expected fxs and gxs inputs for Keyed-Sumcheck gadget");
        };

        let fxs = Self::tracked_cols_from_table(&fxs_table);
        let gxs = Self::tracked_cols_from_table(&gxs_table);

        let mfxs = Self::multiplicities_from_table(payload.get(MFXS_LABEL).cloned(), fxs.len());
        let mgxs = Self::multiplicities_from_table(payload.get(MGXS_LABEL).cloned(), gxs.len());

        let keyed_sumcheck_input = KeyedSumcheckProverInput {
            fxs,
            gxs,
            mfxs,
            mgxs,
        };
        KeyedSumcheck::<B>::prove(prover, keyed_sumcheck_input)?;
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
        verifier: &mut ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for Keyed-Sumcheck gadget node");
        };

        let (Some(fxs_table), Some(gxs_table)) = (
            payload.get(FXS_LABEL).cloned(),
            payload.get(GXS_LABEL).cloned(),
        ) else {
            panic!("Expected fxs and gxs inputs for Keyed-Sumcheck gadget");
        };

        let fxs = Self::tracked_cols_from_table_oracle(&fxs_table);
        let gxs = Self::tracked_cols_from_table_oracle(&gxs_table);

        let mfxs =
            Self::multiplicities_from_table_oracle(payload.get(MFXS_LABEL).cloned(), fxs.len());
        let mgxs =
            Self::multiplicities_from_table_oracle(payload.get(MGXS_LABEL).cloned(), gxs.len());

        let keyed_sumcheck_input = KeyedSumcheckVerifierInput {
            fxs,
            gxs,
            mfxs,
            mgxs,
        };
        KeyedSumcheck::<B>::verify(verifier, keyed_sumcheck_input)?;
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
        Self {
            phantom: std::marker::PhantomData,
        }
    }

    fn tracked_cols_from_table(table: &TrackedTable<B>) -> Vec<TrackedCol<B>> {
        table
            .data_tracked_polys_indices()
            .into_iter()
            .map(|idx| table.tracked_col_by_ind(idx))
            .collect()
    }

    fn multiplicities_from_table(
        table: Option<TrackedTable<B>>,
        expected_len: usize,
    ) -> Vec<Option<ark_piop::prover::structs::polynomial::TrackedPoly<B>>> {
        match table {
            Some(table) => {
                let data_indices = table.data_tracked_polys_indices();
                debug_assert_eq!(
                    data_indices.len(),
                    expected_len,
                    "Keyed-Sumcheck multiplicities must align with inputs."
                );
                data_indices
                    .into_iter()
                    .map(|idx| Some(table.tracked_col_by_ind(idx).data_tracked_poly()))
                    .collect()
            }
            None => vec![None; expected_len],
        }
    }

    fn tracked_cols_from_table_oracle(table: &TrackedTableOracle<B>) -> Vec<TrackedColOracle<B>> {
        table
            .data_tracked_oracles_indices()
            .into_iter()
            .map(|idx| table.tracked_col_oracle_by_ind(idx))
            .collect()
    }

    fn multiplicities_from_table_oracle(
        table: Option<TrackedTableOracle<B>>,
        expected_len: usize,
    ) -> Vec<Option<ark_piop::verifier::structs::oracle::TrackedOracle<B>>> {
        match table {
            Some(table) => {
                let data_indices = table.data_tracked_oracles_indices();
                debug_assert_eq!(
                    data_indices.len(),
                    expected_len,
                    "Keyed-Sumcheck multiplicities must align with inputs."
                );
                data_indices
                    .into_iter()
                    .map(|idx| Some(table.tracked_col_oracle_by_ind(idx).data_tracked_oracle()))
                    .collect()
            }
            None => vec![None; expected_len],
        }
    }
}

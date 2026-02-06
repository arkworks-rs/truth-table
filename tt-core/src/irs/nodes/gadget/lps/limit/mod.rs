use ark_piop::SnarkBackend;
use datafusion_expr::Limit;
use indexmap::IndexMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::irs::{
    nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
    payloads::PayloadStructure,
};
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;
pub const INPUT_ACTIVATOR_LABEL: &str = "__input_activator__";
pub const OUTPUT_ACTIVATOR_LABEL: &str = "__output_activator__";
use ark_ff::Zero;
pub struct GadgetNode<B: SnarkBackend> {
    pub phantom: std::marker::PhantomData<B>,
    limit: Limit,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Limit".to_string()
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

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![]
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
        _prover: &mut ark_piop::prover::ArgProver<B>,
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
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        assert_no_skip(&self.limit);
        // Limit gadget prover: read the precomputed contiguous size `s` and
        // prove sum(output.activator) = i via sumcheck.
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let Some(output_table) = payload.get(OUTPUT_ACTIVATOR_LABEL).cloned() else {
            return Ok(());
        };

        let data_indices = output_table.data_tracked_polys_indices();
        let output_act = match data_indices.as_slice() {
            [idx] => output_table.tracked_col_by_ind(*idx).data_tracked_poly(),
            _ => panic!("Limit gadget expects a single output activator column"),
        };

        let sum_key = format!("limit_contig_sum_{}", limit_key(&self.limit));
        let claimed_sum = prover.miscellaneous_field_element(&sum_key)?;

        prover.add_mv_sumcheck_claim(output_act.id(), claimed_sum)?;
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

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        assert_no_skip(&self.limit);
        // Limit gadget verifier: read the precomputed contiguous size `s` and
        // verify sum(output.activator) = i via sumcheck.
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let Some(output_table) = payload.get(OUTPUT_ACTIVATOR_LABEL).cloned() else {
            return Ok(());
        };

        let data_indices = output_table.data_tracked_oracles_indices();
        let output_act = match data_indices.as_slice() {
            [idx] => output_table.tracked_col_oracle_by_ind(*idx).data_tracked_oracle(),
            _ => panic!("Limit gadget expects a single output activator column"),
        };

        let sum_key = format!("limit_contig_sum_{}", limit_key(&self.limit));
        let claimed_sum = verifier.miscellaneous_field_element(&sum_key)?;

        verifier.add_sumcheck_claim(output_act.id(), claimed_sum);
        Ok(())
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(limit: Limit) -> Self {
        Self {
            limit,
            phantom: std::marker::PhantomData,
        }
    }
}

fn limit_key(limit: &Limit) -> u64 {
    let skip = match limit.get_skip_type() {
        Ok(datafusion_expr::SkipType::Literal(val)) => Some(val),
        _ => None,
    };
    let fetch = match limit.get_fetch_type() {
        Ok(datafusion_expr::FetchType::Literal(val)) => val,
        _ => None,
    };
    let mut hasher = DefaultHasher::new();
    (skip, fetch).hash(&mut hasher);
    hasher.finish()
}

fn assert_no_skip(limit: &Limit) {
    match limit.get_skip_type() {
        Ok(datafusion_expr::SkipType::Literal(val)) if val == 0 => {}
        Ok(datafusion_expr::SkipType::Literal(val)) => {
            panic!("Limit skip is not supported (skip={val})");
        }
        Ok(datafusion_expr::SkipType::UnsupportedExpr) => {
            panic!("Limit skip expression is not supported");
        }
        Err(err) => {
            panic!("Limit skip parsing error: {err}");
        }
    }
}

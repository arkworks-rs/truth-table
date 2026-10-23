use ark_piop::{SnarkBackend, verifier::ArgVerifier};
use datafusion::datasource::{MemTable, TableProvider};
use datafusion_common::DataFusionError;
use proof_planner::data_dependent_lp_optimizer::apply_optimization_hints;
use std::sync::Arc;
use tracing::debug;
use tt_core::session::session_context;
use tt_core::{
    ctx_oracles::CtxOracles,
    errors::{TTError, TTResult},
    irs::shared_ir::{EmptyIr, GadgetPlannedIr, OutputPlannedIr},
    verifier::{
        irs::{GadgetReadyIr as VerifierGadgetReadyIr, VirtualizedIr as VerifierVirtualizedIr},
        passes::{
            gadget_initialization::GadgetInitializationPass as VerifierGadgetInitializationPass,
            gadget_planning::GadgetPlanningPass as VerifierGadgetPlanningPass,
            output_planning::OutputPlanningPass as VerifierOutputPlanningPass,
            tracking::TrackingPass as VerifierTrackingPass, verify::VerifyPass,
            virtualization::VirtualizationPass as VerifierVirtualizationPass,
        },
    },
};

use crate::{shared::TTSharedConfig, structs::TTProof};

pub struct TTVerifierConfig<B: SnarkBackend> {
    phantom: std::marker::PhantomData<B>,
}

impl<B: SnarkBackend> TTVerifierConfig<B> {
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }

    pub fn planning_pass(&self) -> VerifierOutputPlanningPass<B> {
        VerifierOutputPlanningPass::new()
    }

    pub fn gadget_planning_pass(
        &self,
        planned_ir: &OutputPlannedIr<B>,
    ) -> VerifierGadgetPlanningPass<B> {
        VerifierGadgetPlanningPass::new(planned_ir)
    }

    /// `side_columns` (from `Tree::required_side_columns`) are the columns
    /// whose char-level side commitments the prover emits.
    pub fn tracking_pass(
        &self,
        arg_verifier: ArgVerifier<B>,
        ctx_oracles: CtxOracles<B>,
        output_memtable: Option<Arc<MemTable>>,
        side_columns: std::collections::BTreeSet<String>,
        fingerprint_columns: arithmetic::encoding::FingerprintSelection,
        fingerprint_openings: tt_core::prover::passes::tracking::FingerprintOpenings,
    ) -> VerifierTrackingPass<B> {
        VerifierTrackingPass::new(
            arg_verifier,
            ctx_oracles,
            output_memtable,
            side_columns,
            fingerprint_columns,
            fingerprint_openings,
        )
    }
}

impl<B: SnarkBackend> Default for TTVerifierConfig<B> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct TTVerifier<B: SnarkBackend> {
    verifier_config: TTVerifierConfig<B>,
    shared_config: TTSharedConfig<B>,
    arg_verifier: ArgVerifier<B>,
}

impl<B: SnarkBackend> TTVerifier<B> {
    pub fn new(
        verifier_config: TTVerifierConfig<B>,
        shared_config: TTSharedConfig<B>,
        arg_verifier: ArgVerifier<B>,
    ) -> Self {
        Self {
            verifier_config,
            shared_config,
            arg_verifier,
        }
    }

    /// Verifies a proof from a precomputed gadget-planned IR and an optional
    /// prover-supplied output table.
    pub async fn verify_with_gadget_planned_ir(
        &self,
        proof: &TTProof<B>,
        gadget_planned_ir: &GadgetPlannedIr<B>,
        output_memtable: Option<Arc<MemTable>>,
    ) -> TTResult<()> {
        let snark_proof = proof.as_snark_proof();
        let mut arg_verifier = self.arg_verifier.fork();
        arg_verifier.set_proof_ref(snark_proof);

        // The side-column set comes from the same IR tree the prover used, so
        // both sides expect the same per-column side commitments without a
        // wire hint.
        let side_columns = gadget_planned_ir.tree().required_side_columns();
        let fingerprint_columns = gadget_planned_ir.tree().required_fingerprint_columns();
        let verifier_tracking_pass = self.verifier_config.tracking_pass(
            arg_verifier.clone(),
            self.shared_config.ctx_oracles().clone(),
            output_memtable,
            side_columns,
            fingerprint_columns,
            proof.fingerprint_openings().clone(),
        );
        let mut tracked_ir = gadget_planned_ir.apply_local_pass_sequential(&verifier_tracking_pass);
        verifier_tracking_pass.finish(&mut tracked_ir).await?;

        let verifier_virtualization_pass = VerifierVirtualizationPass::<B>::new(&tracked_ir);
        let virtualized_ir = tracked_ir.apply_local_pass_sequential(&verifier_virtualization_pass);

        let gadget_ir_view = VerifierVirtualizedIr::new(
            virtualized_ir.tree().clone(),
            virtualized_ir.payloads().clone(),
        );

        let gadget_initialization_pass =
            VerifierGadgetInitializationPass::<B>::new(gadget_ir_view, arg_verifier.clone());
        let gadget_ready_ir =
            virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);

        let verify_ir_view = VerifierGadgetReadyIr::new(
            gadget_ready_ir.tree().clone(),
            gadget_ready_ir.payloads().clone(),
        );

        let verify_pass = VerifyPass::<B>::new(arg_verifier.clone(), verify_ir_view);
        let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&verify_pass);

        verify_pass.take_result().map_err(|err| {
            TTError::DataFusion(DataFusionError::Internal(format!(
                "verifier verify_pass failed before cryptographic verification: {err:?}"
            )))
        })?;
        arg_verifier.verify().map_err(|err| {
            TTError::DataFusion(DataFusionError::Internal(format!(
                "verifier cryptographic verification failed: {err:?}"
            )))
        })?;
        Ok(())
    }

    /// Verifies a proof end to end: replays the LP and IR pipelines and
    /// normalizes (activator column, padding) the prover-supplied output table.
    pub async fn verify(
        &self,
        query: &str,
        proof: &TTProof<B>,
        result: Arc<MemTable>,
    ) -> TTResult<()> {
        let lp = self.lp_passes(query, proof).await?;
        let gadget_planned_ir = self.ir_passes(lp).await?;
        let ctx = session_context();
        let df = ctx.read_table(result.clone())?;
        let batches = df.collect().await?;
        let base_schema = batches
            .first()
            .map(|batch| batch.schema().as_ref().clone())
            .unwrap_or_else(|| result.schema().as_ref().clone());
        let (output_schema, output_batches) =
            tt_core::prover::passes::materialization::append_activator_and_pad_batches(
                &base_schema,
                batches,
            )?;
        let output_memtable = Arc::new(MemTable::try_new(
            Arc::new(output_schema),
            vec![output_batches],
        )?);
        self.verify_with_gadget_planned_ir(proof, &gadget_planned_ir, Some(output_memtable))
            .await
    }

    /// Runs the verifier logical-plan pipeline, replaying the optimization
    /// hints embedded in the proof.
    pub async fn lp_passes(
        &self,
        query: &str,
        proof: &TTProof<B>,
    ) -> TTResult<datafusion_expr::LogicalPlan> {
        let initial_lp = self.shared_config.query_to_lp(query).await;
        debug!(
            "verifier initial logical plan:\n{}",
            initial_lp.display_graphviz()
        );

        let analyzed_lp = self.shared_config.analyze_lp(initial_lp).await;
        let analyzed_and_optimized_lp = self.shared_config.optimize_lp(analyzed_lp).await;

        // Replay the prover's data-dependent choices from the proof.
        let analyzed_and_optimized_lp =
            apply_optimization_hints(analyzed_and_optimized_lp, proof.optimization_hints())
                .map_err(tt_core::errors::TTError::from)?;
        debug!(
            "verifier optimized and analyzed logical plan:\n{}",
            analyzed_and_optimized_lp.display_graphviz()
        );
        Ok(analyzed_and_optimized_lp)
    }

    /// Runs the verifier IR pipeline up through gadget planning.
    pub async fn ir_passes(
        &self,
        lp: datafusion_expr::LogicalPlan,
    ) -> TTResult<GadgetPlannedIr<B>> {
        tt_core::irs::supported::ensure_supported(&lp)?;
        let initial_ir = EmptyIr::<B>::from_logical_plan(&lp);
        debug!(
            "verifier initial ir:\n{}",
            initial_ir.display_graphviz(true)
        );

        let optimized_initial_ir = self.shared_config.pp_optimizer().optimize(initial_ir);
        debug!(
            "verifier optimized initial ir:\n{}",
            optimized_initial_ir.display_graphviz(true)
        );

        let output_planned_ir =
            optimized_initial_ir.apply_local_pass_sequential(&self.verifier_config.planning_pass());
        let gadget_planned_ir = output_planned_ir.apply_local_pass_sequential(
            &self
                .verifier_config
                .gadget_planning_pass(&output_planned_ir),
        );
        debug!(
            "verifier gadget planned ir:\n{}",
            gadget_planned_ir.display_graphviz(true)
        );
        Ok(gadget_planned_ir)
    }
}

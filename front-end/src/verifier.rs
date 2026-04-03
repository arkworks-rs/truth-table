use ark_piop::{verifier::ArgVerifier, SnarkBackend};
use datafusion::{
    datasource::{MemTable, TableProvider},
    prelude::SessionContext,
};
use datafusion_common::DataFusionError;
use proof_planner::{
    logical_plan_optimizer::apply_optimization_hints,
    proof_plan_optimizer::{rules as proof_plan_rules, ProofPlanOptimizer},
};
use std::sync::Arc;
use tracing::debug;
use tt_core::{
    ctx_oracles::CtxOracles,
    errors::{TTError, TTResult},
    irs::shared_ir::{EmptyIr, GadgetPlannedIr, OutputPlannedIr},
    irs::tree::Tree,
    verifier::{
        irs::{
            GadgetReadyIr as VerifierGadgetReadyIr, VirtualizedIr as VerifierVirtualizedIr,
        },
        passes::{
            gadget_initialization::GadgetInitializationPass as VerifierGadgetInitializationPass,
            gadget_planning::GadgetPlanningPass as VerifierGadgetPlanningPass,
            output_planning::OutputPlanningPass as VerifierOutputPlanningPass,
            tracking::TrackingPass as VerifierTrackingPass,
            verify::VerifyPass,
            virtualization::VirtualizationPass as VerifierVirtualizationPass,
        },
    },
};

use crate::{shared::TTSharedConfig, structs::TTProof};

// Truth Table verifier configuration
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

    pub fn tracking_pass(
        &self,
        arg_verifier: ArgVerifier<B>,
        ctx_oracles: CtxOracles<B>,
        output_memtable: Option<Arc<MemTable>>,
    ) -> VerifierTrackingPass<B> {
        VerifierTrackingPass::new(arg_verifier, ctx_oracles, output_memtable)
    }
}

impl<B: SnarkBackend> Default for TTVerifierConfig<B> {
    fn default() -> Self {
        Self::new()
    }
}

/// Truth Table Verifier
pub struct TTVerifier<B: SnarkBackend> {
    /// The configuration specific to the verifier
    verifier_config: TTVerifierConfig<B>,
    /// The configuration shared between prover and verifier
    shared_config: TTSharedConfig<B>,
    /// The inner argument verifier
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

    pub fn verifier_config(&self) -> &TTVerifierConfig<B> {
        &self.verifier_config
    }
    pub fn shared_config(&self) -> &TTSharedConfig<B> {
        &self.shared_config
    }
    pub fn arg_verifier(&self) -> &ArgVerifier<B> {
        &self.arg_verifier
    }

    pub async fn verify_with_gadget_planned_ir(
        &self,
        proof: &TTProof<B>,
        gadget_planned_ir: &GadgetPlannedIr<B>,
        output_memtable: Option<Arc<MemTable>>,
    ) -> TTResult<()> {
        // Step 1: Parse and prepare the initial IR from the proof
        let snark_proof = proof.as_snark_proof();
        let mut arg_verifier = self.arg_verifier().fork();
        arg_verifier.set_proof_ref(snark_proof);

        // Step 2: Apply the tracking pass
        let verifier_tracking_pass = self.verifier_config().tracking_pass(
            arg_verifier.clone(),
            self.shared_config().ctx_oracles().clone(),
            output_memtable,
        );
        let mut tracked_ir = gadget_planned_ir.apply_local_pass_sequential(&verifier_tracking_pass);
        verifier_tracking_pass.finish(&mut tracked_ir).await?;

        // Step 3: Apply the virtualization pass
        let verifier_virtualization_pass = VerifierVirtualizationPass::<B>::new(&tracked_ir);
        let virtualized_ir = tracked_ir.apply_local_pass_sequential(&verifier_virtualization_pass);

        let gadget_ir_view = VerifierVirtualizedIr::new(
            virtualized_ir.tree().clone(),
            virtualized_ir.payloads().clone(),
        );

        // Step 4: Apply the gadget initialization pass
        let gadget_initialization_pass =
            VerifierGadgetInitializationPass::<B>::new(gadget_ir_view, arg_verifier.clone());
        let gadget_ready_ir =
            virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);

        let verify_ir_view = VerifierGadgetReadyIr::new(
            gadget_ready_ir.tree().clone(),
            gadget_ready_ir.payloads().clone(),
        );

        // Step 5: Apply the verification pass
        let verify_pass = VerifyPass::<B>::new(arg_verifier.clone(), verify_ir_view);
        let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&verify_pass);

        // Step 6: Verify the SNARK verification
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

    pub async fn verify(
        &self,
        query: &str,
        proof: &TTProof<B>,
        result: Arc<MemTable>,
    ) -> TTResult<()> {
        let lp = self.lp_passes(query, proof).await?;
        let gadget_planned_ir = self.ir_passes(lp).await?;
        let ctx = SessionContext::new();
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

    pub async fn lp_passes(
        &self,
        query: &str,
        proof: &TTProof<B>,
    ) -> TTResult<datafusion_expr::LogicalPlan> {
        let initial_lp = self.shared_config().query_to_lp(query).await;
        debug!(
            "verifier initial logical plan:\n{}",
            initial_lp.display_graphviz()
        );
        let analyzed_lp = self.shared_config().analyze_lp(initial_lp).await;
        let analyzed_and_optimized_lp = self.shared_config().optimize_lp(analyzed_lp).await;
        let analyzed_and_optimized_lp =
            apply_optimization_hints(analyzed_and_optimized_lp, proof.optimization_hints())
                .map_err(tt_core::errors::TTError::from)?;
        debug!(
            "verifier optimized and analyzed logical plan:\n{}",
            analyzed_and_optimized_lp.display_graphviz()
        );
        Ok(analyzed_and_optimized_lp)
    }

    pub async fn ir_passes(
        &self,
        lp: datafusion_expr::LogicalPlan,
    ) -> TTResult<GadgetPlannedIr<B>> {
        let tree: Tree<B> = Tree::from_logical_plan(&lp);
        let initial_ir = EmptyIr::<B>::new_empty(tree);
        debug!(
            "verifier initial ir:\n{}",
            initial_ir.display_graphviz(true)
        );
        let proof_plan_optimizer = ProofPlanOptimizer::new(proof_plan_rules());
        let optimized_initial_ir = proof_plan_optimizer.optimize(initial_ir);
        debug!(
            "verifier optimized initial ir:\n{}",
            optimized_initial_ir.display_graphviz(true)
        );
        let output_planned_ir = optimized_initial_ir
            .apply_local_pass_sequential(&self.verifier_config().planning_pass());
        let gadget_planned_ir = output_planned_ir.apply_local_pass_sequential(
            &self
                .verifier_config()
                .gadget_planning_pass(&output_planned_ir),
        );
        debug!(
            "verifier gadget planned ir:\n{}",
            gadget_planned_ir.display_graphviz(true)
        );
        Ok(gadget_planned_ir)
    }
}

use ark_piop::{verifier::ArgVerifier, SnarkBackend};
use tt_core::{
    ctx_oracles::CtxOracles,
    errors::TTResult,
    irs::shared_ir::{EmptyIr, GadgetPlannedIr, OutputPlannedIr},
    verifier::{
        irs::{
            GadgetReadyIr as VerifierGadgetReadyIr, TrackedIr as VerifierTrackedIr,
            VirtualizedIr as VerifierVirtualizedIr,
        },
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

pub struct VerifierIrStages<B: SnarkBackend> {
    pub initial: EmptyIr<B>,
    pub output_planned: OutputPlannedIr<B>,
    pub gadget_planned: GadgetPlannedIr<B>,
    pub tracked: VerifierTrackedIr<B>,
    pub virtualized: VerifierVirtualizedIr<B>,
    pub gadget_ready: VerifierGadgetReadyIr<B>,
}

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
    ) -> VerifierTrackingPass<B> {
        VerifierTrackingPass::new(arg_verifier, ctx_oracles)
    }
}

impl<B: SnarkBackend> Default for TTVerifierConfig<B> {
    fn default() -> Self {
        Self::new()
    }
}

/// Verifier configuration that bundles planner rules and context oracles.
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

    pub fn verifier_config(&self) -> &TTVerifierConfig<B> {
        &self.verifier_config
    }
    pub fn shared_config(&self) -> &TTSharedConfig<B> {
        &self.shared_config
    }
    pub fn arg_verifier(&self) -> &ArgVerifier<B> {
        &self.arg_verifier
    }

    fn gadget_planned_ir_for_query(&self, _query: &str, proof: &TTProof<B>) -> GadgetPlannedIr<B> {
        let initial_ir = proof.optimized_ir().clone();
        let output_planned_ir =
            initial_ir.apply_local_pass_sequential(&self.verifier_config().planning_pass());
        let gadget_planned_ir = output_planned_ir.apply_local_pass_sequential(
            &self
                .verifier_config()
                .gadget_planning_pass(&output_planned_ir),
        );
        gadget_planned_ir
    }

    async fn verify_with_gadget_planned_ir(
        &self,
        proof: &TTProof<B>,
        gadget_planned_ir: &GadgetPlannedIr<B>,
    ) -> TTResult<()> {
        let snark_proof = proof.as_inner();
        let mut arg_verifier = self.arg_verifier().fork();
        arg_verifier.set_proof_ref(snark_proof);

        let verifier_tracking_pass = self.verifier_config().tracking_pass(
            arg_verifier.clone(),
            self.shared_config().ctx_oracles().clone(),
        );
        let tracked_ir = gadget_planned_ir.apply_local_pass_sequential(&verifier_tracking_pass);
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
        verify_pass.take_result()?;

        arg_verifier.verify()?;
        Ok(())
    }

    pub async fn verify(&self, query: &str, proof: &TTProof<B>) -> TTResult<()> {
        // Fast path used by production verification and verifier benches.
        let gadget_planned_ir = self.gadget_planned_ir_for_query(query, proof);
        self.verify_with_gadget_planned_ir(proof, &gadget_planned_ir)
            .await
    }

    pub async fn verify_with_preprocessed(
        &self,
        proof: &TTProof<B>,
        gadget_planned_ir: &GadgetPlannedIr<B>,
    ) -> TTResult<()> {
        self.verify_with_gadget_planned_ir(proof, gadget_planned_ir)
            .await
    }

    /// Run verifier planning for a query/proof pair (output + gadget planning only).
    ///
    /// This intentionally excludes tracking/virtualization/gadget-init/verify passes
    /// and excludes cryptographic verification.
    pub fn preprocess_query(&self, query: &str, proof: &TTProof<B>) -> GadgetPlannedIr<B> {
        self.gadget_planned_ir_for_query(query, proof)
    }

    pub async fn build_ir_stages(
        &self,
        query: &str,
        proof: &TTProof<B>,
    ) -> TTResult<(VerifierIrStages<B>, ArgVerifier<B>)> {
        let snark_proof = proof.as_inner();
        let initial_ir = proof.optimized_ir().clone();
        // debug!("initial ir:\n{}", initial_ir.display_graphviz(true));
        let output_planned_ir =
            initial_ir.apply_local_pass_sequential(&self.verifier_config().planning_pass());
        // debug!(
        //     "output planned ir:\n{}",
        //     output_planned_ir.display_graphviz(true)
        // );
        let gadget_planned_ir = self.gadget_planned_ir_for_query(query, proof);
        // debug!(
        //     "gadget planned ir:\n{}",
        //     gadget_planned_ir.display_graphviz(true)
        // );

        let mut arg_verifier = self.arg_verifier().fork();
        arg_verifier.set_proof_ref(snark_proof);

        let verifier_tracking_pass = self.verifier_config().tracking_pass(
            arg_verifier.clone(),
            self.shared_config().ctx_oracles().clone(),
        );
        let tracked_ir = gadget_planned_ir.apply_local_pass_sequential(&verifier_tracking_pass);
        // debug!("tracked ir:\n{}", tracked_ir.display_graphviz(true));
        let verifier_virtualization_pass = VerifierVirtualizationPass::<B>::new(&tracked_ir);
        let virtualized_ir = tracked_ir.apply_local_pass_sequential(&verifier_virtualization_pass);
        // debug!("virtualized ir:\n{}", virtualized_ir.display_graphviz(true));
        let gadget_ir_view = VerifierVirtualizedIr::new(
            virtualized_ir.tree().clone(),
            virtualized_ir.payloads().clone(),
        );
        let gadget_initialization_pass =
            VerifierGadgetInitializationPass::<B>::new(gadget_ir_view, arg_verifier.clone());
        let gadget_ready_ir =
            virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);
        // debug!(
        //     "gadget ready ir:\n{}",
        //     gadget_ready_ir.display_graphviz(true)
        // );

        let verify_ir_view = VerifierGadgetReadyIr::new(
            gadget_ready_ir.tree().clone(),
            gadget_ready_ir.payloads().clone(),
        );
        let verify_pass = VerifyPass::<B>::new(arg_verifier.clone(), verify_ir_view);
        let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&verify_pass);
        verify_pass.take_result()?;

        Ok((
            VerifierIrStages {
                initial: initial_ir,
                output_planned: output_planned_ir,
                gadget_planned: gadget_planned_ir,
                tracked: tracked_ir,
                virtualized: virtualized_ir,
                gadget_ready: gadget_ready_ir,
            },
            arg_verifier,
        ))
    }
}

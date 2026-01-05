use ark_piop::{verifier::ArgVerifier, SnarkBackend};
use tt_core::{
    errors::TTResult,
    irs::{
        shared_ir::{EmptyIr, PlannedIr},
        shared_passes::{GadgetPlanningPass, OutputPlanningPass},
        tree::Tree,
    },
    verifier::{
        irs::{
            GadgetReadyIr as VerifierGadgetReadyIr, TrackedIr as VerifierTrackedIr,
            VirtualizedIr as VerifierVirtualizedIr,
        },
        passes::{
            gadget_initialization::GadgetInitializationPass as VerifierGadgetInitializationPass,
            tracking::TrackingPass as VerifierTrackingPass, verify::VerifyPass,
            virtualization::VirtualizationPass as VerifierVirtualizationPass,
        },
    },
};

use crate::{shared::TTSharedConfig, structs::TTProof};

pub struct VerifierIrStages<B: SnarkBackend> {
    pub initial: EmptyIr<B>,
    pub planned: PlannedIr<B>,
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

    pub fn planning_pass(&self) -> OutputPlanningPass<B> {
        OutputPlanningPass::new()
    }
    pub fn gadget_planning_pass(&self) -> GadgetPlanningPass<B> {
        GadgetPlanningPass::new()
    }

    pub fn tracking_pass(&self, arg_verifier: ArgVerifier<B>) -> VerifierTrackingPass<B> {
        VerifierTrackingPass::new(arg_verifier)
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

    pub async fn verify(&self, query: &str, proof: TTProof<B>) -> TTResult<()> {
        let (_stages, mut arg_verifier) = self.build_ir_stages(query, proof).await?;
        arg_verifier.verify()?;
        Ok(())
    }

    pub async fn build_ir_stages(
        &self,
        query: &str,
        proof: TTProof<B>,
    ) -> TTResult<(VerifierIrStages<B>, ArgVerifier<B>)> {
        let initial_lp = self.shared_config().query_to_lp(query).await;
        let analyzed_and_optimized_lp = self
            .shared_config()
            .analyze_and_optimize_lp(initial_lp)
            .await;
        let tree: Tree<B> = Tree::from_logical_plan(&analyzed_and_optimized_lp);

        let initial_ir = EmptyIr::<B>::new_empty(tree);
        let mut planned_ir =
            initial_ir.apply_local_pass_parallel(&self.verifier_config().planning_pass());
        let gadget_planned_ir =
            initial_ir.apply_local_pass_sequential(&self.verifier_config().gadget_planning_pass());
        for (id, payload) in gadget_planned_ir.payloads().iter() {
            if planned_ir.payload_for_node(id).is_none() {
                planned_ir.set_payload_for_node(*id, payload.clone());
            }
        }

        let mut arg_verifier = self.arg_verifier().clone();
        arg_verifier.set_proof(proof.into_inner());

        let verifier_tracking_pass = self.verifier_config().tracking_pass(arg_verifier.clone());
        let tracked_ir = planned_ir.apply_local_pass_sequential(&verifier_tracking_pass);
        let verifier_virtualization_pass = VerifierVirtualizationPass::<B>::new(&tracked_ir);
        let virtualized_ir = tracked_ir.apply_local_pass_sequential(&verifier_virtualization_pass);
        let gadget_ir_view = VerifierVirtualizedIr::new(
            virtualized_ir.tree().clone(),
            virtualized_ir.payloads().clone(),
        );
        let gadget_initialization_pass = VerifierGadgetInitializationPass::<B>::new(gadget_ir_view);
        let gadget_ready_ir =
            virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);

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
                planned: planned_ir,
                tracked: tracked_ir,
                virtualized: virtualized_ir,
                gadget_ready: gadget_ready_ir,
            },
            arg_verifier,
        ))
    }
}

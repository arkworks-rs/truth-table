use arithmetic::table_oracle::{ArithTableOracle, TrackedTableOracle};
use ark_piop::{
    prover::ArgProver,
    setup::structs::SNARKPk,
    verifier::ArgVerifier,
    SnarkBackend,
};
use proof_planner::{
    logical_plan_optimizer::{apply_optimization_hints, collect_data_dependent_hints},
    proof_plan_optimizer::{ProofPlanOptimizer, rules as proof_plan_rules},
};
use tracing::debug;
#[cfg(feature = "honest-prover")]
use tt_core::prover::passes::honest_prover::HonestProverPass;
use tt_core::errors::TTResult;
use tt_core::{
    irs::{shared_ir::EmptyIr, tree::Tree},
    prover::{
        irs::{GadgetReadyIr as ProverGadgetReadyIr, VirtualizedIr as ProverVirtualizedIr},
        passes::{
            gadget_initialization::GadgetInitializationPass,
            proving::ProvingPass,
            virtualization::VirtualizationPass,
        },
    },
};

use crate::{
    shared::{TTSharedConfig, table_scan_payload},
    structs::TTProof,
};

/// Data-owner configuration for table commitment generation.
pub struct TTDataOwnerConfig<B: SnarkBackend> {
    phantom: std::marker::PhantomData<B>,
}

impl<B: SnarkBackend> TTDataOwnerConfig<B> {
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }
}

impl<B: SnarkBackend> Default for TTDataOwnerConfig<B> {
    fn default() -> Self {
        Self::new()
    }
}

/// Data owner that can commit table-scan outputs into serializable oracle
/// artifacts without exposing the raw table data to the verifier.
pub struct TTDataOwner<B: SnarkBackend> {
    data_owner_config: TTDataOwnerConfig<B>,
    shared_config: TTSharedConfig<B>,
    snark_pk: SNARKPk<B>,
}

impl<B: SnarkBackend> TTDataOwner<B> {
    pub fn new(
        data_owner_config: TTDataOwnerConfig<B>,
        shared_config: TTSharedConfig<B>,
        snark_pk: SNARKPk<B>,
    ) -> Self {
        Self {
            data_owner_config,
            shared_config,
            snark_pk,
        }
    }

    pub fn data_owner_config(&self) -> &TTDataOwnerConfig<B> {
        &self.data_owner_config
    }

    pub fn shared_config(&self) -> &TTSharedConfig<B> {
        &self.shared_config
    }

    pub fn snark_pk(&self) -> &SNARKPk<B> {
        &self.snark_pk
    }

    pub async fn commit(&self, query: &str) -> TTResult<ArithTableOracle<B>> {
        let initial_lp = self.shared_config().query_to_lp(query).await;
        debug!("Initial Logical plan{}", initial_lp.display_graphviz());
        let analyzed_lp = self.shared_config().analyze_lp(initial_lp).await;
        let analyzed_and_optimized_lp = self.shared_config().optimize_lp(analyzed_lp).await;
        let optimization_hints =
            collect_data_dependent_hints(self.shared_config().session_ctx(), &analyzed_and_optimized_lp)?;
        let analyzed_and_optimized_lp =
            apply_optimization_hints(analyzed_and_optimized_lp, &optimization_hints)?;
        debug!(
            "optimized and analyzed logical plan:\n{}",
            analyzed_and_optimized_lp.display_graphviz()
        );
        let tree: Tree<B> = Tree::from_logical_plan(&analyzed_and_optimized_lp);
        let initial_ir = EmptyIr::<B>::new_empty(tree);
        debug!("initial ir:\n{}", initial_ir.display_graphviz(true));
        let proof_plan_optimizer = ProofPlanOptimizer::new(proof_plan_rules());
        let optimized_initial_ir = proof_plan_optimizer.optimize(initial_ir);
        debug!(
            "optimized initial ir:\n{}",
            optimized_initial_ir.display_graphviz(true)
        );
        let output_planned_ir = optimized_initial_ir.apply_local_pass_parallel(
            &tt_core::prover::passes::output_planning::OutputPlanningPass::new(),
        );
        debug!(
            "output planned ir:\n{}",
            output_planned_ir.display_graphviz(true)
        );
        let gadget_planned_ir = output_planned_ir.apply_local_pass_sequential(
            &tt_core::prover::passes::gadget_planning::GadgetPlanningPass::new(&output_planned_ir),
        );
        drop(output_planned_ir);
        debug!(
            "gadget planned ir:\n{}",
            gadget_planned_ir.display_graphviz(true)
        );
        let materialized_ir = gadget_planned_ir.apply_local_pass_parallel(
            &tt_core::prover::passes::materialization::MaterializationPass::new(),
        );
        drop(gadget_planned_ir);
        debug!("materialized ir:\n{}", materialized_ir.display_graphviz(true));
        let arithmetized_ir = materialized_ir.apply_local_pass_parallel(
            &tt_core::prover::passes::arithmetization::ArithmetizationPass::new(),
        );
        drop(materialized_ir);
        debug!(
            "arithmetized ir:\n{}",
            arithmetized_ir.display_graphviz(true)
        );
        let arg_prover = ArgProver::new_from_pk(self.snark_pk().clone());
        let committed_ir = arithmetized_ir.apply_local_pass_parallel(
            &tt_core::prover::passes::commitment::CommitmentPass::new(
                arg_prover.mv_pcs_prover_param(),
                self.shared_config().ctx_oracles().clone(),
                true,
            ),
        );
        debug!("committed ir:\n{}", committed_ir.display_graphviz(true));
        let tracked_ir = committed_ir.apply_local_pass_sequential(
            &tt_core::prover::passes::tracking::TrackingPass::new(
                arg_prover.clone(),
                arithmetized_ir.payloads(),
                None,
            ),
        );
        drop(arithmetized_ir);
        drop(committed_ir);
        debug!("tracked ir:\n{}", tracked_ir.display_graphviz(true));
        let table_scan = table_scan_payload(&tracked_ir)?;
        let virtualization_pass = VirtualizationPass::<B>::new(&tracked_ir);
        let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);
        debug!("virtualized ir:\n{}", virtualized_ir.display_graphviz(true));
        let gadget_ir_view = ProverVirtualizedIr::new(
            virtualized_ir.tree().clone(),
            virtualized_ir.payloads().clone(),
        );
        let gadget_initialization_pass =
            GadgetInitializationPass::<B>::new(gadget_ir_view, arg_prover.clone());
        let gadget_ready_ir =
            virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);
        drop(virtualized_ir);
        debug!("gadget ready ir:\n{}", gadget_ready_ir.display_graphviz(true));
        let proving_ir_view = ProverGadgetReadyIr::new(
            gadget_ready_ir.tree().clone(),
            gadget_ready_ir.payloads().clone(),
        );
        #[cfg(feature = "honest-prover")]
        {
            let honest_ir_view = ProverGadgetReadyIr::new(
                gadget_ready_ir.tree().clone(),
                gadget_ready_ir.payloads().clone(),
            );
            let honest_prover_pass =
                HonestProverPass::<B>::new(arg_prover.deep_copy(), honest_ir_view);
            let _honest_ir = gadget_ready_ir.apply_local_pass_sequential(&honest_prover_pass);
            honest_prover_pass.take_result()?;
        }
        let proving_pass = ProvingPass::<B>::new(arg_prover.clone(), proving_ir_view);
        let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&proving_pass);
        drop(gadget_ready_ir);
        proving_pass.take_result()?;
        let mut arg_prover = arg_prover;
        let arg_proof = arg_prover.build_proof().unwrap();
        let tt_proof = TTProof::new(arg_proof, optimization_hints)?;

        let mut verifier = ArgVerifier::new_from_vk(self.snark_pk().vk.clone());
        verifier.set_proof(tt_proof.snark_proof());

        let tracked_table_oracle =
            TrackedTableOracle::from_tracked_table(table_scan, &mut verifier)?;
        Ok(ArithTableOracle::from_tracked_table_oracle(
            &tracked_table_oracle,
        ))
    }
}

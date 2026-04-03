use std::{cell::RefCell, sync::Arc};

use ark_piop::{pcs::PCS, prover::ArgProver, SnarkBackend};
use datafusion::{dataframe::DataFrame, datasource::MemTable};
use datafusion_expr::LogicalPlan;
use indexmap::IndexMap;
use proof_planner::{
    logical_plan_optimizer::{
        apply_optimization_hints, collect_data_dependent_hints, OptimizationHints,
    },
    proof_plan_optimizer::{rules as proof_plan_rules, ProofPlanOptimizer},
};
use tracing::debug;
#[cfg(feature = "honest-prover")]
use tt_core::prover::passes::honest_prover::HonestProverPass;
use tt_core::{
    ctx_oracles::CtxOracles,
    errors::TTResult,
    irs::{
        nodes::NodeId,
        shared_ir::{EmptyIr, OutputPlannedIr},
    },
    prover::{
        irs::{GadgetReadyIr as ProverGadgetReadyIr, VirtualizedIr as ProverVirtualizedIr},
        passes::{
            arithmetization::ArithmetizationPass, commitment::CommitmentPass,
            gadget_initialization::GadgetInitializationPass,
            gadget_planning::GadgetPlanningPass as ProverGadgetPlanningPass,
            materialization::MaterializationPass,
            output_planning::OutputPlanningPass as ProverOutputPlanningPass, proving::ProvingPass,
            tracking::TrackingPass, virtualization::VirtualizationPass,
        },
        payloads::ArithPayload,
    },
};

use crate::{shared::TTSharedConfig, structs::TTProof};

pub struct TTProverConfig<B: SnarkBackend> {
    phantom: std::marker::PhantomData<B>,
}
impl<B: SnarkBackend> TTProverConfig<B> {
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }
    pub fn output_planning_pass(&self) -> ProverOutputPlanningPass<B> {
        ProverOutputPlanningPass::new()
    }
    pub fn gadget_planning_pass(
        &self,
        planned_ir: &OutputPlannedIr<B>,
    ) -> ProverGadgetPlanningPass<B> {
        ProverGadgetPlanningPass::new(planned_ir)
    }
    pub fn materialization_pass(&self) -> MaterializationPass<B> {
        MaterializationPass::new()
    }
    pub fn arithmetization_pass(&self) -> ArithmetizationPass<B> {
        ArithmetizationPass::new()
    }
    pub fn commitment_pass(
        &self,
        mv_pcs_param: Arc<<B::MvPCS as PCS<B::F>>::ProverParam>,
        ctx_oracles: CtxOracles<B>,
    ) -> CommitmentPass<B> {
        CommitmentPass::new(mv_pcs_param, ctx_oracles, false)
    }
    pub fn tracking_pass<'a>(
        &self,
        arg_prover: ArgProver<B>,
        arith_payloads: &'a IndexMap<NodeId, Option<ArithPayload<B::F>>>,
        result: Option<Arc<MemTable>>,
    ) -> TrackingPass<'a, B> {
        TrackingPass::new(arg_prover, arith_payloads, result)
    }
}

impl<B: SnarkBackend> Default for TTProverConfig<B> {
    fn default() -> Self {
        Self::new()
    }
}

/// Prover configuration that bundles planner rules and context oracles.
pub struct TTProver<B: SnarkBackend> {
    /// The configuration specific to the prover
    prover_config: TTProverConfig<B>,
    /// The configuration shared between prover and verifier
    shared_config: TTSharedConfig<B>,
    /// The inner argument prover
    arg_prover: RefCell<ArgProver<B>>,
}

impl<B: SnarkBackend> TTProver<B> {
    pub fn new(
        prover_config: TTProverConfig<B>,
        shared_config: TTSharedConfig<B>,
        arg_prover: ArgProver<B>,
    ) -> Self {
        Self {
            prover_config,
            shared_config,
            arg_prover: RefCell::new(arg_prover),
        }
    }

    pub fn prover_config(&self) -> &TTProverConfig<B> {
        &self.prover_config
    }
    pub fn shared_config(&self) -> &TTSharedConfig<B> {
        &self.shared_config
    }
    pub fn arg_prover(&self) -> std::cell::Ref<'_, ArgProver<B>> {
        self.arg_prover.borrow()
    }

    // Perform passes over the logical plan
    async fn lp_passes(&self, query: &str) -> TTResult<(LogicalPlan, OptimizationHints)> {
        let initial_lp = self.shared_config().query_to_lp(query).await;
        debug!("Initial Logical plan{}", initial_lp.display_graphviz());

        let analyzed_lp = self.shared_config().analyze_lp(initial_lp).await;
        debug!("Analyzed Logical plan{}", analyzed_lp.display_graphviz());

        let structural_optimized_lp = self.shared_config().optimize_lp(analyzed_lp).await;
        debug!(
            "Optimized Logical plan{}",
            structural_optimized_lp.display_graphviz()
        );

        let optimization_hints = collect_data_dependent_hints(
            self.shared_config().session_ctx(),
            &structural_optimized_lp,
        )?;
        let data_dependent_optimized_lp =
            apply_optimization_hints(structural_optimized_lp, &optimization_hints)?;
        debug!(
            "optimized and analyzed logical plan:\n{}",
            data_dependent_optimized_lp.display_graphviz()
        );

        Ok((data_dependent_optimized_lp, optimization_hints))
    }

    // Perform passes over the Intermediate Representation (IR)
    async fn ir_passes(
        &self,
        initial_ir: EmptyIr<B>,
        result: Arc<MemTable>,
    ) -> TTResult<()> {
        debug!("initial ir:\n{}", initial_ir.display_graphviz(true));
        // 1. Proof plan optimization passes
        let proof_plan_optimizer = ProofPlanOptimizer::new(proof_plan_rules());
        let optimized_initial_ir = proof_plan_optimizer.optimize(initial_ir);
        debug!(
            "optimized initial ir:\n{}",
            optimized_initial_ir.display_graphviz(true)
        );
        // 2. Output planning pass
        let output_planned_ir = optimized_initial_ir
            .apply_local_pass_parallel(&self.prover_config().output_planning_pass());
        debug!(
            "output planned ir:\n{}",
            output_planned_ir.display_graphviz(true)
        );
        // 3. Gadget planning pass
        let gadget_planned_ir = output_planned_ir.apply_local_pass_sequential(
            &self
                .prover_config()
                .gadget_planning_pass(&output_planned_ir),
        );
        drop(output_planned_ir);
        debug!(
            "gadget planned ir:\n{}",
            gadget_planned_ir.display_graphviz(true)
        );
        // 4. Materialization pass
        let materialized_ir = gadget_planned_ir
            .apply_local_pass_parallel(&self.prover_config().materialization_pass());
        drop(gadget_planned_ir);
        debug!(
            "materialized ir:\n{}",
            materialized_ir.display_graphviz(true)
        );
        // 5. Arithmetization pass
        let arithmetized_ir =
            materialized_ir.apply_local_pass_parallel(&self.prover_config().arithmetization_pass());
        drop(materialized_ir);
        debug!(
            "arithmetized ir:\n{}",
            arithmetized_ir.display_graphviz(true)
        );
        // 6. Commitment pass
        let arg_prover = self.arg_prover.borrow().clone();
        let committed_ir =
            arithmetized_ir.apply_local_pass_parallel(&self.prover_config().commitment_pass(
                arg_prover.mv_pcs_prover_param(),
                self.shared_config().ctx_oracles().clone(),
            ));
        debug!("committed ir:\n{}", committed_ir.display_graphviz(true));
        // 7. Tracking pass
        let tracked_ir = {
            let tracking_pass = self.prover_config().tracking_pass(
                arg_prover.clone(),
                arithmetized_ir.payloads(),
                Some(result.clone()),
            );
            let mut tracked_ir = committed_ir.apply_local_pass_sequential(&tracking_pass);
            tracking_pass.finish(&mut tracked_ir).await?;
            tracked_ir
        };
        drop(arithmetized_ir);
        drop(committed_ir);
        debug!("tracked ir:\n{}", tracked_ir.display_graphviz(true));
        // 8. Virtualization pass
        let virtualization_pass = VirtualizationPass::<B>::new(&tracked_ir);
        let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);
        drop(tracked_ir);
        debug!("virtualized ir:\n{}", virtualized_ir.display_graphviz(true));
        let gadget_ir_view = ProverVirtualizedIr::new(
            virtualized_ir.tree().clone(),
            virtualized_ir.payloads().clone(),
        );
        // 9. Gadget initialization pass
        let gadget_initialization_pass =
            GadgetInitializationPass::<B>::new(gadget_ir_view, arg_prover.clone());
        let gadget_ready_ir =
            virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);
        drop(virtualized_ir);
        debug!(
            "gadget ready ir:\n{}",
            gadget_ready_ir.display_graphviz(true)
        );
        // 10. Honest prover pass (optional, behind feature flag)
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
        // 11. Proving pass
        let proving_pass = ProvingPass::<B>::new(arg_prover.clone(), proving_ir_view);
        let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&proving_pass);
        drop(gadget_ready_ir);
        proving_pass.take_result()?;

        Ok(())
    }

    // Prove the query execution
    pub async fn prove(&self, query: &str) -> TTResult<(Arc<MemTable>, TTProof<B>)> {
        // 1. Compute the result of the query execution
        let result = self.execute(query).await?;
        // 2. Perform logical plan passes such as analysis and optimizations and collect data-dependent hints to be sent to the verifier
        let (lp, optimization_hints) = self.lp_passes(query).await?;
        // 3. Convert the logical plan to a truth-table IR
        let initial_ir = EmptyIr::<B>::from_logical_plan(&lp);
        // 4. Perform IR passes
        self.ir_passes(initial_ir, Arc::clone(&result)).await?;
        // 5. Assemble the truth-table proof
        let tt_proof = self.assemble_proof(optimization_hints)?;
        Ok((result, tt_proof))
    }

    /// Assemble the truth-table proof
    fn assemble_proof(&self, optimization_hints: OptimizationHints) -> TTResult<TTProof<B>> {
        let arg_proof = self.arg_prover.borrow_mut().build_proof().unwrap();
        TTProof::new(arg_proof, optimization_hints)
    }

    // Execute the query
    async fn execute(&self, query: &str) -> TTResult<Arc<MemTable>> {
        let lp = self.shared_config().query_to_lp(query).await;
        let analyzed_lp = self.shared_config().analyze_lp(lp).await;
        let optimized_lp = self.shared_config().optimize_lp(analyzed_lp).await;
        let df = DataFrame::new(self.shared_config().session_ctx().state(), optimized_lp);
        let logical_schema = df.schema().as_arrow().clone();
        let batches = df.collect().await?;
        let mem_table = MemTable::try_new(Arc::new(logical_schema), vec![batches])?;
        Ok(Arc::new(mem_table))
    }
}

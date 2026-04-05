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
use std::time::Instant;
use tracing::{debug, info};
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
use std::future::Future;

pub struct TTProverConfig<B: SnarkBackend> {
    phantom: std::marker::PhantomData<B>,
}
impl<B: SnarkBackend> TTProverConfig<B> {
    /// Create the default prover-side pass factory.
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }

    /// Build the prover output-planning pass.
    pub fn output_planning_pass(&self) -> ProverOutputPlanningPass<B> {
        ProverOutputPlanningPass::new()
    }

    /// Build the prover gadget-planning pass for a planned IR.
    pub fn gadget_planning_pass(
        &self,
        planned_ir: &OutputPlannedIr<B>,
    ) -> ProverGadgetPlanningPass<B> {
        ProverGadgetPlanningPass::new(planned_ir)
    }

    /// Build the materialization pass.
    pub fn materialization_pass(&self) -> MaterializationPass<B> {
        MaterializationPass::new()
    }

    /// Build the arithmetization pass.
    pub fn arithmetization_pass(&self) -> ArithmetizationPass<B> {
        ArithmetizationPass::new()
    }

    /// Build the commitment pass using the prover PCS parameters and context oracles.
    pub fn commitment_pass(
        &self,
        mv_pcs_param: Arc<<B::MvPCS as PCS<B::F>>::ProverParam>,
        ctx_oracles: CtxOracles<B>,
    ) -> CommitmentPass<B> {
        CommitmentPass::new(mv_pcs_param, ctx_oracles, false)
    }

    /// Build the tracking pass for the current arithmetized payloads and optional query result.
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
    /// Create a prover from its pass configuration, shared configuration, and inner SNARK prover.
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

    /// Borrow the prover-specific configuration.
    fn prover_config(&self) -> &TTProverConfig<B> {
        &self.prover_config
    }

    /// Borrow the configuration shared between the prover and verifier.
    fn shared_config(&self) -> &TTSharedConfig<B> {
        &self.shared_config
    }

    /// Emit a named Graphviz artifact into the bench-stats tracing stream.
    fn emit_plan_graphviz(&self, name: &str, graphviz: impl Into<String>) {
        info!(target: "bench_stats", plan_name = name, plan_graphviz = graphviz.into(), "plan");
    }

    /// Record a logical-plan snapshot for debugging and dashboard display.
    fn record_logical_plan(&self, name: &str, plan: &LogicalPlan) {
        let graphviz = plan.display_graphviz().to_string();
        debug!("{name}:\n{graphviz}");
        self.emit_plan_graphviz(name, graphviz);
    }

    /// Emit a Graphviz snapshot for an IR stage.
    fn emit_ir_graphviz(&self, name: &str, graphviz: String) {
        self.emit_plan_graphviz(name, graphviz);
    }

    /// Record the timing and Graphviz output for a completed IR stage.
    fn record_ir_stage(
        &self,
        pass_name: &str,
        plan_name: &str,
        started_at: Instant,
        graphviz: String,
    ) {
        self.emit_pass_timing(pass_name, started_at);
        debug!("{plan_name}:\n{graphviz}");
        self.emit_ir_graphviz(plan_name, graphviz);
    }

    /// Run an IR stage, time it, and emit its rendered Graphviz view.
    async fn timed_ir_stage<T, F, Fut>(
        &self,
        pass_name: &str,
        plan_name: &str,
        run: F,
        graphviz: impl FnOnce(&T) -> String,
    ) -> TTResult<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = TTResult<T>>,
    {
        let started_at = Instant::now();
        let output = run().await?;
        self.record_ir_stage(pass_name, plan_name, started_at, graphviz(&output));
        Ok(output)
    }

    /// Emit a prover pass timing sample to the bench-stats tracing stream.
    fn emit_pass_timing(&self, pass_name: &str, started_at: Instant) {
        info!(
            target: "bench_stats",
            prover_time_pass = pass_name,
            prover_time_seconds = started_at.elapsed().as_secs_f64(),
            "prover_time"
        );
    }

    /// Run the logical-plan pipeline and return the optimized plan together with
    /// the verifier-facing hints needed to replay data-dependent optimizer choices.
    async fn lp_passes(&self, query: &str) -> TTResult<(LogicalPlan, OptimizationHints)> {
        // 1. Build the raw logical plan from the SQL query.
        let initial_lp = self.shared_config().query_to_lp(query).await;
        self.record_logical_plan("initial_logical_plan", &initial_lp);

        // 2. Run analysis so later optimizer stages work with a fully resolved plan.
        let analyzed_lp = self.shared_config().analyze_lp(initial_lp).await;
        self.record_logical_plan("analyzed_logical_plan", &analyzed_lp);

        // 3. Apply the structural optimizer rules that do not depend on runtime data.
        let structural_optimized_lp = self.shared_config().optimize_lp(analyzed_lp).await;
        self.record_logical_plan("structural_optimized_logical_plan", &structural_optimized_lp);

        // 4. Collect the data-dependent optimization hints that must travel in the proof.
        let optimization_hints = collect_data_dependent_hints(
            self.shared_config().session_ctx(),
            &structural_optimized_lp,
        )?;

        // 5. Materialize those hints into the final logical plan that the prover uses.
        let data_dependent_optimized_lp =
            apply_optimization_hints(structural_optimized_lp, &optimization_hints)?;
        self.record_logical_plan(
            "data_dependent_optimized_logical_plan",
            &data_dependent_optimized_lp,
        );

        Ok((data_dependent_optimized_lp, optimization_hints))
    }

    /// Run the prover IR pipeline from the empty IR through the proving pass.
    async fn ir_passes(&self, initial_ir: EmptyIr<B>, result: Arc<MemTable>) -> TTResult<()> {
        debug!("initial ir:\n{}", initial_ir.display_graphviz(true));
        self.emit_ir_graphviz("initial_ir", initial_ir.display_graphviz(true));
        // 1. Proof plan optimization passes
        let proof_plan_optimizer = ProofPlanOptimizer::new(proof_plan_rules());
        let optimized_initial_ir = proof_plan_optimizer.optimize(initial_ir);
        debug!(
            "optimized initial ir:\n{}",
            optimized_initial_ir.display_graphviz(true)
        );
        self.emit_ir_graphviz(
            "optimized_initial_ir",
            optimized_initial_ir.display_graphviz(true),
        );
        // 2. Output planning pass
        let output_planned_ir = self
            .timed_ir_stage(
                "output_planning",
                "output_planned_ir",
                || async {
                    Ok(optimized_initial_ir
                        .apply_local_pass_parallel(&self.prover_config().output_planning_pass()))
                },
                |ir| ir.display_graphviz(true),
            )
            .await?;
        // 3. Gadget planning pass
        let gadget_planned_ir = self
            .timed_ir_stage(
                "gadget_planning",
                "gadget_planned_ir",
                || async {
                    Ok(output_planned_ir.apply_local_pass_sequential(
                        &self
                            .prover_config()
                            .gadget_planning_pass(&output_planned_ir),
                    ))
                },
                |ir| ir.display_graphviz(true),
            )
            .await?;
        drop(output_planned_ir);
        // 4. Materialization pass
        let materialized_ir = self
            .timed_ir_stage(
                "materialization",
                "materialized_ir",
                || async {
                    Ok(gadget_planned_ir
                        .apply_local_pass_parallel(&self.prover_config().materialization_pass()))
                },
                |ir| ir.display_graphviz(true),
            )
            .await?;
        drop(gadget_planned_ir);
        // 5. Arithmetization pass
        let arithmetized_ir = self
            .timed_ir_stage(
                "arithmetization",
                "arithmetized_ir",
                || async {
                    Ok(materialized_ir
                        .apply_local_pass_parallel(&self.prover_config().arithmetization_pass()))
                },
                |ir| ir.display_graphviz(true),
            )
            .await?;
        drop(materialized_ir);
        // 6. Commitment pass
        let arg_prover = self.arg_prover.borrow().clone();
        let committed_ir = self
            .timed_ir_stage(
                "commitment",
                "committed_ir",
                || async {
                    Ok(arithmetized_ir.apply_local_pass_parallel(
                        &self.prover_config().commitment_pass(
                            arg_prover.mv_pcs_prover_param(),
                            self.shared_config().ctx_oracles().clone(),
                        ),
                    ))
                },
                |ir| ir.display_graphviz(true),
            )
            .await?;
        // 7. Tracking pass
        let tracked_ir = self
            .timed_ir_stage(
                "tracking",
                "tracked_ir",
                || async {
                    let tracking_pass = self.prover_config().tracking_pass(
                        arg_prover.clone(),
                        arithmetized_ir.payloads(),
                        Some(result.clone()),
                    );
                    let mut tracked_ir = committed_ir.apply_local_pass_sequential(&tracking_pass);
                    tracking_pass.finish(&mut tracked_ir).await?;
                    Ok::<_, tt_core::errors::TTError>(tracked_ir)
                },
                |ir| ir.display_graphviz(true),
            )
            .await?;
        drop(arithmetized_ir);
        drop(committed_ir);
        // 8. Virtualization pass
        let virtualized_ir = self
            .timed_ir_stage(
                "virtualization",
                "virtualized_ir",
                || async {
                    let virtualization_pass = VirtualizationPass::<B>::new(&tracked_ir);
                    Ok(tracked_ir.apply_local_pass_sequential(&virtualization_pass))
                },
                |ir| ir.display_graphviz(true),
            )
            .await?;
        drop(tracked_ir);
        let gadget_ir_view = ProverVirtualizedIr::new(
            virtualized_ir.tree().clone(),
            virtualized_ir.payloads().clone(),
        );
        // 9. Gadget initialization pass
        let gadget_ready_ir = self
            .timed_ir_stage(
                "gadget_initialization",
                "gadget_ready_ir",
                || async {
                    let gadget_initialization_pass =
                        GadgetInitializationPass::<B>::new(gadget_ir_view, arg_prover.clone());
                    Ok(virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass))
                },
                |ir| ir.display_graphviz(true),
            )
            .await?;
        drop(virtualized_ir);
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
        let proving_started = Instant::now();
        let proving_pass = ProvingPass::<B>::new(arg_prover.clone(), proving_ir_view);
        let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&proving_pass);
        drop(gadget_ready_ir);
        proving_pass.take_result()?;
        self.emit_pass_timing("proving_pass", proving_started);

        Ok(())
    }

    /// Execute the query, run the prover pipeline, and assemble the final proof artifact.
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

    /// Execute the optimized query and return the raw result table that will be sent to the verifier.
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

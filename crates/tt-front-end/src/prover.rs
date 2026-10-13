use std::{cell::RefCell, sync::Arc};

use ark_piop::{SnarkBackend, pcs::PCS, prover::ArgProver};
use datafusion::{dataframe::DataFrame, datasource::MemTable};
use datafusion_common::tree_node::Transformed;
use datafusion_expr::LogicalPlan;
use indexmap::IndexMap;
use proof_planner::data_dependent_lp_optimizer::{OptimizationHints, apply_optimization_hints};
use tracing::{Instrument, Span, debug, info, info_span};
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
use arithmetic::ACTIVATOR_COL_NAME;
use datafusion_expr::{col, logical_plan::Filter};
use std::future::Future;

/// Tracing target for spans and events the bench-stats subscriber consumes.
pub const BENCH_STATS_TARGET: &str = "bench_stats";

/// Span wrapping one prover pass. Its `pass` field names the pass and its
/// lifetime is the pass's duration. The subscriber turns each one into the
/// `prover_time_<pass>_s` entry and the `prover_pass_spans` marker the
/// dashboard overlays on the RSS curve.
pub const PROVER_PASS_SPAN: &str = "prover_pass";

/// Name of the field on [`PROVER_PASS_SPAN`] carrying the pass name.
pub const PROVER_PASS_FIELD: &str = "pass";

/// The [`PROVER_PASS_SPAN`] of one prover pass.
pub fn pass_span(pass_name: &str) -> Span {
    info_span!(target: BENCH_STATS_TARGET, "prover_pass", pass = pass_name)
}

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

    /// `side_columns` (from `Tree::required_side_columns`) are the columns
    /// white-box string gadgets consume char-level side polys for; no other
    /// string column gets side polys. `fingerprint_columns` (from
    /// `Tree::required_fingerprint_columns`) are the table-scan columns that
    /// carry fingerprint limbs.
    pub fn arithmetization_pass(
        &self,
        side_columns: std::collections::BTreeSet<String>,
        fingerprint_columns: arithmetic::encoding::FingerprintSelection,
    ) -> ArithmetizationPass<B> {
        ArithmetizationPass::new(
            side_columns,
            tt_core::prover::passes::arithmetization::FingerprintColumns::Only(fingerprint_columns),
        )
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

pub struct TTProver<B: SnarkBackend> {
    prover_config: TTProverConfig<B>,
    shared_config: TTSharedConfig<B>,
    arg_prover: RefCell<ArgProver<B>>,
    /// The fingerprint multiproofs the tracking pass produced, for the proof.
    fingerprint_openings: RefCell<tt_core::prover::passes::tracking::FingerprintOpenings>,
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
            fingerprint_openings: RefCell::new(Vec::new()),
        }
    }

    fn emit_plan_graphviz(&self, name: &str, graphviz: impl Into<String>) {
        info!(target: "bench_stats", plan_name = name, plan_graphviz = graphviz.into(), "plan");
    }

    fn record_logical_plan(&self, name: &str, plan: &LogicalPlan) {
        let graphviz = plan.display_graphviz().to_string();
        debug!("{name}:\n{graphviz}");
        self.emit_plan_graphviz(name, graphviz);
    }

    /// Logs and emits the Graphviz of a completed IR stage. Its duration
    /// comes from [`pass_span`].
    fn record_ir_stage(&self, plan_name: &str, graphviz: String) {
        debug!("{plan_name}:\n{graphviz}");
        self.emit_plan_graphviz(plan_name, graphviz);
    }

    /// Runs an IR stage inside its [`pass_span`] and emits its Graphviz view.
    /// The span closes at the end of the `run(...).await` statement, so it
    /// covers the stage and not the Graphviz rendering.
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
        let output = run().instrument(pass_span(pass_name)).await?;
        self.record_ir_stage(plan_name, graphviz(&output));
        Ok(output)
    }

    /// Runs the logical-plan pipeline. Returns the optimized plan and the hints
    /// the verifier needs to replay the data-dependent optimizer's choices.
    async fn lp_passes(&self, query: &str) -> TTResult<(LogicalPlan, OptimizationHints)> {
        let initial_lp = self.shared_config.query_to_lp(query).await;
        self.record_logical_plan("initial_logical_plan", &initial_lp);

        let analyzed_lp = self.shared_config.analyze_lp(initial_lp).await;
        self.record_logical_plan("analyzed_logical_plan", &analyzed_lp);

        // The structural rules do not depend on the data.
        let structural_optimized_lp = self.shared_config.optimize_lp(analyzed_lp).await;
        self.record_logical_plan(
            "structural_optimized_logical_plan",
            &structural_optimized_lp,
        );

        // The data-dependent hints travel in the proof.
        let optimization_hints = self
            .shared_config
            .data_dependent_optimizer()
            .collect_hints(self.shared_config.session_ctx(), &structural_optimized_lp)?;

        let data_dependent_optimized_lp =
            apply_optimization_hints(structural_optimized_lp, &optimization_hints)?;
        self.record_logical_plan(
            "data_dependent_optimized_logical_plan",
            &data_dependent_optimized_lp,
        );

        Ok((data_dependent_optimized_lp, optimization_hints))
    }

    /// Runs the prover IR pipeline from the empty IR through the proving pass.
    async fn ir_passes(&self, initial_ir: EmptyIr<B>, result: Arc<MemTable>) -> TTResult<()> {
        debug!("initial ir:\n{}", initial_ir.display_graphviz(true));
        self.emit_plan_graphviz("initial_ir", initial_ir.display_graphviz(true));
        let optimized_initial_ir = self.shared_config.pp_optimizer().optimize(initial_ir);
        debug!(
            "optimized initial ir:\n{}",
            optimized_initial_ir.display_graphviz(true)
        );
        self.emit_plan_graphviz(
            "optimized_initial_ir",
            optimized_initial_ir.display_graphviz(true),
        );
        let output_planned_ir = self
            .timed_ir_stage(
                "output_planning",
                "output_planned_ir",
                || async {
                    Ok(optimized_initial_ir
                        .apply_local_pass_parallel(&self.prover_config.output_planning_pass()))
                },
                |ir| ir.display_graphviz(true),
            )
            .await?;
        let gadget_planned_ir = self
            .timed_ir_stage(
                "gadget_planning",
                "gadget_planned_ir",
                || async {
                    Ok(output_planned_ir.apply_local_pass_sequential(
                        &self.prover_config.gadget_planning_pass(&output_planned_ir),
                    ))
                },
                |ir| ir.display_graphviz(true),
            )
            .await?;
        drop(output_planned_ir);
        let materialized_ir = self
            .timed_ir_stage(
                "materialization",
                "materialized_ir",
                || async {
                    Ok(gadget_planned_ir
                        .apply_local_pass_parallel(&self.prover_config.materialization_pass()))
                },
                |ir| ir.display_graphviz(true),
            )
            .await?;
        drop(gadget_planned_ir);
        // Char-level side polys are emitted only for columns some white-box
        // string gadget (e.g. LIKE) consumes. The set comes from the shared IR
        // tree, so the verifier reaches the same decision without a wire hint.
        let side_columns = materialized_ir.tree().required_side_columns();
        info!(?side_columns, "columns receiving char-level side polys");
        let fingerprint_columns = materialized_ir.tree().required_fingerprint_columns();
        let arithmetized_ir = self
            .timed_ir_stage(
                "arithmetization",
                "arithmetized_ir",
                || async {
                    Ok(materialized_ir.apply_local_pass_parallel(
                        &self
                            .prover_config
                            .arithmetization_pass(side_columns, fingerprint_columns),
                    ))
                },
                |ir| ir.display_graphviz(true),
            )
            .await?;
        drop(materialized_ir);
        let arg_prover = self.arg_prover.borrow().clone();
        let committed_ir = self
            .timed_ir_stage(
                "commitment",
                "committed_ir",
                || async {
                    Ok(arithmetized_ir.apply_local_pass_parallel(
                        &self.prover_config.commitment_pass(
                            arg_prover.mv_pcs_prover_param(),
                            self.shared_config.ctx_oracles().clone(),
                        ),
                    ))
                },
                |ir| ir.display_graphviz(true),
            )
            .await?;
        let tracked_ir = self
            .timed_ir_stage(
                "tracking",
                "tracked_ir",
                || async {
                    let tracking_pass = self.prover_config.tracking_pass(
                        arg_prover.clone(),
                        arithmetized_ir.payloads(),
                        Some(result.clone()),
                    );
                    let mut tracked_ir = committed_ir.apply_local_pass_sequential(&tracking_pass);
                    tracking_pass.finish(&mut tracked_ir).await?;
                    self.fingerprint_openings
                        .replace(tracking_pass.take_fingerprint_openings());
                    Ok::<_, tt_core::errors::TTError>(tracked_ir)
                },
                |ir| ir.display_graphviz(true),
            )
            .await?;
        drop(arithmetized_ir);
        drop(committed_ir);
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
        {
            let _pass = pass_span("proving_pass").entered();
            let proving_pass = ProvingPass::<B>::new(arg_prover.clone(), proving_ir_view);
            let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&proving_pass);
            drop(gadget_ready_ir);
            proving_pass.take_result()?;
        }

        Ok(())
    }

    /// Executes the query and proves it. Returns the result table and the
    /// proof.
    pub async fn prove(&self, query: &str) -> TTResult<(Arc<MemTable>, TTProof<B>)> {
        let result = self.execute(query).await?;
        let (lp, optimization_hints) = self.lp_passes(query).await?;
        let initial_ir = EmptyIr::<B>::from_logical_plan(&lp);
        self.ir_passes(initial_ir, Arc::clone(&result)).await?;
        let tt_proof = self.assemble_proof(optimization_hints)?;
        Ok((result, tt_proof))
    }

    fn assemble_proof(&self, optimization_hints: OptimizationHints) -> TTResult<TTProof<B>> {
        let arg_proof = self.arg_prover.borrow_mut().build_proof().unwrap();
        TTProof::new(
            arg_proof,
            optimization_hints,
            self.fingerprint_openings.take(),
        )
    }

    /// The query's result table, which is sent to the verifier.
    async fn execute(&self, query: &str) -> TTResult<Arc<MemTable>> {
        let lp = self.shared_config.query_to_lp(query).await;
        let analyzed_lp = self.shared_config.analyze_lp(lp).await;
        let optimized_lp = self.shared_config.optimize_lp(analyzed_lp).await;
        let optimized_lp = filter_inactive_rows_for_execution(optimized_lp)?;
        let df = DataFrame::new(self.shared_config.session_ctx().state(), optimized_lp);
        let logical_schema = df.schema().as_arrow().clone();
        let batches = df.collect().await?;
        let mem_table = MemTable::try_new(Arc::new(logical_schema), vec![batches])?;
        Ok(Arc::new(mem_table))
    }
}

fn filter_inactive_rows_for_execution(plan: LogicalPlan) -> TTResult<LogicalPlan> {
    Ok(plan
        .transform_up_with_subqueries(|node| {
            let LogicalPlan::TableScan(scan) = node else {
                return Ok(Transformed::no(node));
            };

            let projected_has_activator = scan
                .projected_schema
                .fields()
                .iter()
                .any(|field| field.name() == ACTIVATOR_COL_NAME);
            if !projected_has_activator {
                return Ok(Transformed::no(LogicalPlan::TableScan(scan)));
            }

            let filtered = LogicalPlan::Filter(Filter::try_new(
                col(ACTIVATOR_COL_NAME),
                Arc::new(LogicalPlan::TableScan(scan)),
            )?);
            Ok(Transformed::yes(filtered))
        })?
        .data)
}

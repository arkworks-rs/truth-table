use std::{cell::RefCell, sync::Arc};

use ark_piop::{SnarkBackend, pcs::PCS, prover::ArgProver};
use datafusion::execution::SessionStateBuilder;
use datafusion::functions_aggregate::expr_fn::min;
use datafusion::functions_window::expr_fn::row_number;
use datafusion::optimizer::{Optimizer, OptimizerRule};
use datafusion::{dataframe::DataFrame, datasource::MemTable};
use datafusion_common::Column;
use datafusion_common::tree_node::Transformed;
use datafusion_expr::{
    Aggregate, Expr, ExprFunctionExt, LogicalPlan, LogicalPlanBuilder, Projection, Sort,
    SubqueryAlias, TableScan,
};
use indexmap::IndexMap;
use proof_planner::data_dependent_lp_optimizer::{OptimizationHints, apply_optimization_hints};
use proof_planner::lp_optimizer::FetchSafePushDownFilter;
use tracing::{Instrument, Span, debug, info, info_span};
use tt_core::irs::nodes::plan::lps::join::modes::{JoinMode, decide_join_mode};
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
use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
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
            tt_core::prover::passes::arithmetization::SideColumns::Only(side_columns),
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
        tt_core::irs::supported::ensure_supported(&lp)?;
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
        // Before the activator filters: join modes are decided on plain scans.
        let optimized_lp =
            ProofRowOrder::new(self.shared_config.pp_optimizer().specializes_pk_fk_joins())
                .apply(optimized_lp)?;
        let optimized_lp = filter_inactive_rows_for_execution(optimized_lp)?;
        // DataFusion's default pipeline, with its PushDownFilter replaced by
        // the one that keeps a filter above a top-k.
        let state = self.shared_config.session_ctx().state();
        let fetch_safe: Arc<dyn OptimizerRule + Send + Sync> =
            Arc::new(FetchSafePushDownFilter::new());
        let rules = Optimizer::new()
            .rules
            .into_iter()
            .map(|rule| {
                if rule.name() == fetch_safe.name() {
                    Arc::clone(&fetch_safe)
                } else {
                    rule
                }
            })
            .collect();
        let state = SessionStateBuilder::new_from_existing(state)
            .with_optimizer_rules(rules)
            .build();
        let df = DataFrame::new(state, optimized_lp);
        let logical_schema = df.schema().as_arrow().clone();
        let batches = df.collect().await?;
        #[cfg(feature = "test-utils")]
        let batches = tt_core::test_utils::dishonest_prover::claimed_result(batches);
        let mem_table = MemTable::try_new(Arc::new(logical_schema), vec![batches])?;
        Ok(Arc::new(mem_table))
    }
}

/// Orders rows tied on every sort key as the proof's Sort does (`sort_df`), by
/// its input's `__row_id__`, so that a LIMIT cutting through tied rows keeps
/// the rows the proof keeps. The result is still computed here, apart from
/// the proof.
///
/// The proof numbers each node's rows from its inputs' row orders: a join by
/// (left, right), or by its foreign-key side when proved as a PK-FK join; a
/// GROUP BY by each group's first row. That order is rebuilt as one column,
/// threaded up to each Sort and projected away above it (projection pushdown
/// drops `__row_id__` from the scans).
struct ProofRowOrder {
    specializes_pk_fk_joins: bool,
    columns: usize,
}

impl ProofRowOrder {
    fn new(specializes_pk_fk_joins: bool) -> Self {
        Self {
            specializes_pk_fk_joins,
            columns: 0,
        }
    }

    fn apply(&mut self, plan: LogicalPlan) -> TTResult<LogicalPlan> {
        Ok(plan
            .transform_up_with_subqueries(|node| {
                let LogicalPlan::Sort(sort) = node else {
                    return Ok(Transformed::no(node));
                };
                let Some((input, order)) = self.with_order(sort.input.as_ref())? else {
                    return Ok(Transformed::no(LogicalPlan::Sort(sort)));
                };
                let output: Vec<Expr> = sort
                    .input
                    .schema()
                    .columns()
                    .into_iter()
                    .map(Expr::Column)
                    .collect();
                let mut expr = sort.expr.clone();
                expr.push(Expr::Column(order).sort(true, true));
                let sorted = LogicalPlan::Sort(Sort {
                    expr,
                    input: Arc::new(input),
                    fetch: sort.fetch,
                });
                Ok(Transformed::yes(LogicalPlan::Projection(
                    Projection::try_new(output, Arc::new(sorted))?,
                )))
            })?
            .data)
    }

    /// `plan` with a further output column ordering its rows as the proof
    /// numbers them, and that column; `None` where that numbering is not
    /// rebuilt.
    fn with_order(
        &mut self,
        plan: &LogicalPlan,
    ) -> datafusion_common::Result<Option<(LogicalPlan, Column)>> {
        let rebuilt = match plan {
            LogicalPlan::TableScan(scan) => {
                let Ok(index) = scan.source.schema().index_of(ROW_ID_COL_NAME) else {
                    return Ok(None);
                };
                let mut projection = scan
                    .projection
                    .clone()
                    .unwrap_or_else(|| (0..scan.source.schema().fields().len()).collect());
                if !projection.contains(&index) {
                    projection.push(index);
                }
                let scan = TableScan::try_new(
                    scan.table_name.clone(),
                    Arc::clone(&scan.source),
                    Some(projection),
                    scan.filters.clone(),
                    scan.fetch,
                )?;
                let order = Column::new(Some(scan.table_name.clone()), ROW_ID_COL_NAME);
                (LogicalPlan::TableScan(scan), order)
            }
            LogicalPlan::Filter(filter) => {
                let Some((input, order)) = self.with_order(&filter.input)? else {
                    return Ok(None);
                };
                let filter = Filter::try_new(filter.predicate.clone(), Arc::new(input))?;
                (LogicalPlan::Filter(filter), order)
            }
            LogicalPlan::Projection(projection) => {
                let Some((input, order)) = self.with_order(&projection.input)? else {
                    return Ok(None);
                };
                let mut expr = projection.expr.clone();
                if !projection.schema.has_column(&order) {
                    expr.push(Expr::Column(order.clone()));
                }
                let projection = Projection::try_new(expr, Arc::new(input))?;
                (LogicalPlan::Projection(projection), order)
            }
            LogicalPlan::SubqueryAlias(alias) => {
                let Some((input, order)) = self.with_order(&alias.input)? else {
                    return Ok(None);
                };
                let alias = SubqueryAlias::try_new(Arc::new(input), alias.alias.clone())?;
                let order = Column::new(Some(alias.alias.clone()), order.name);
                (LogicalPlan::SubqueryAlias(alias), order)
            }
            LogicalPlan::Join(join) => {
                let (Some((left, left_order)), Some((right, right_order))) =
                    (self.with_order(&join.left)?, self.with_order(&join.right)?)
                else {
                    return Ok(None);
                };
                let (left_keys, right_keys) =
                    join.on.iter().cloned().unzip::<_, _, Vec<_>, Vec<_>>();
                let joined = LogicalPlanBuilder::from(left).join_with_expr_keys(
                    right,
                    join.join_type,
                    (left_keys, right_keys),
                    join.filter.clone(),
                )?;
                // A PK-FK join's output row is its foreign-key row; a left
                // foreign-key side already comes first.
                let fk_right =
                    self.specializes_pk_fk_joins && decide_join_mode(join) == JoinMode::ONE_TO_MANY;
                let (first, second) = if fk_right {
                    (right_order, left_order)
                } else {
                    (left_order, right_order)
                };
                let name = self.fresh_name();
                let rank = row_number()
                    .order_by(vec![
                        Expr::Column(first).sort(true, true),
                        Expr::Column(second).sort(true, true),
                    ])
                    .build()?
                    .alias(&name);
                (joined.window(vec![rank])?.build()?, Column::from_name(name))
            }
            LogicalPlan::Aggregate(aggregate) => {
                let Some((input, order)) = self.with_order(&aggregate.input)? else {
                    return Ok(None);
                };
                // A group's output row is its first input row.
                let name = self.fresh_name();
                let mut aggr_expr = aggregate.aggr_expr.clone();
                aggr_expr.push(min(Expr::Column(order)).alias(&name));
                let aggregate =
                    Aggregate::try_new(Arc::new(input), aggregate.group_expr.clone(), aggr_expr)?;
                (LogicalPlan::Aggregate(aggregate), Column::from_name(name))
            }
            _ => return Ok(None),
        };
        Ok(Some(rebuilt))
    }

    fn fresh_name(&mut self) -> String {
        self.columns += 1;
        format!("__proof_row_order_{}__", self.columns)
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

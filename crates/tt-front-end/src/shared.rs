use std::sync::Arc;

use ark_piop::SnarkBackend;
use async_trait::async_trait;
use datafusion::{
    config::ConfigOptions,
    execution::{context::QueryPlanner, session_state::SessionState},
    optimizer::{Analyzer, Optimizer, OptimizerContext, OptimizerRule},
    physical_plan::ExecutionPlan,
    physical_planner::{DefaultPhysicalPlanner, ExtensionPlanner, PhysicalPlanner},
    prelude::SessionContext,
};
use datafusion_common::{DataFusionError, Result as DataFusionResult};
use datafusion_expr::{LogicalPlan, logical_plan::UserDefinedLogicalNode};
use proof_planner::data_dependent_lp_optimizer::{
    DataDependentOptimizer, rules as data_dependent_rules,
};
use proof_planner::data_dependent_pp_optimizer::{
    DataDependentProofPlanOptimizer, rules as data_dependent_pp_rules,
};
use proof_planner::pp_optimizer::{ProofPlanOptimizer, rules as pp_rules};
use tt_core::ctx_oracles::CtxOracles;
use tt_core::irs::nodes::plan::{
    rematerialize::RematerializeLogicalNode, result_check::ResultCheckLogicalNode,
};

/// Shared front-end configuration used by the prover, verifier, and data owner.
///
/// This bundles the DataFusion analyzer/optimizer pipeline together with the
/// query-planning context and the context oracles needed by truth-table passes.
pub struct TTSharedConfig<B: SnarkBackend> {
    analyzer: Analyzer,
    optimizer: Optimizer,
    pp_optimizer: ProofPlanOptimizer<B>,
    data_dependent_optimizer: DataDependentOptimizer,
    data_dependent_pp_optimizer: DataDependentProofPlanOptimizer<B>,
    ctx_oracles: CtxOracles<B>,
    session_ctx: SessionContext,
    config_options: ConfigOptions,
    optimizer_ctx: OptimizerContext,
    observer: fn(&LogicalPlan, &dyn OptimizerRule),
}

impl<B: SnarkBackend> TTSharedConfig<B> {
    #[allow(clippy::too_many_arguments)]
    /// Build a shared configuration from explicit DataFusion components.
    ///
    /// The provided session context is wrapped with a custom query planner so
    /// DataFusion can tolerate our no-op logical extension nodes when a physical
    /// plan is built for query execution.
    pub fn new(
        analyzer: Analyzer,
        optimizer: Optimizer,
        pp_optimizer: ProofPlanOptimizer<B>,
        data_dependent_optimizer: DataDependentOptimizer,
        data_dependent_pp_optimizer: DataDependentProofPlanOptimizer<B>,
        ctx_oracles: CtxOracles<B>,
        session_ctx: SessionContext,
        config_options: ConfigOptions,
        optimizer_ctx: OptimizerContext,
        observer: fn(&LogicalPlan, &dyn OptimizerRule),
    ) -> Self {
        Self {
            analyzer,
            optimizer,
            pp_optimizer,
            data_dependent_optimizer,
            data_dependent_pp_optimizer,
            ctx_oracles,
            session_ctx: with_noop_extension_support(session_ctx),
            config_options,
            optimizer_ctx,
            observer,
        }
    }

    /// Construct the default shared configuration used by front-end components.
    pub fn with_defaults(session_ctx: SessionContext) -> Self {
        Self::new(
            Analyzer::with_rules(proof_planner::lp_analyzer::rules()),
            Optimizer::with_rules(proof_planner::lp_optimizer::rules(&session_ctx)),
            ProofPlanOptimizer::new(pp_rules()),
            DataDependentOptimizer::with_rules(data_dependent_rules()),
            DataDependentProofPlanOptimizer::with_rules(data_dependent_pp_rules()),
            CtxOracles::default(),
            session_ctx,
            ConfigOptions::new(),
            OptimizerContext::new(),
            |_plan_after_rule, _rule| {},
        )
    }

    /// Borrow the shared analyzer.
    pub fn analyzer(&self) -> &Analyzer {
        &self.analyzer
    }

    /// Borrow the shared optimizer.
    pub fn optimizer(&self) -> &Optimizer {
        &self.optimizer
    }

    /// Borrow the shared proof-plan optimizer.
    pub fn pp_optimizer(&self) -> &ProofPlanOptimizer<B> {
        &self.pp_optimizer
    }

    /// Borrow the shared data-dependent optimizer (produces hints the prover
    /// ships with the proof for the verifier to replay).
    pub fn data_dependent_optimizer(&self) -> &DataDependentOptimizer {
        &self.data_dependent_optimizer
    }

    /// Borrow the shared data-dependent proof-plan optimizer. Currently
    /// holds an empty rule list — wired in for future data-dependent IR
    /// optimizations.
    pub fn data_dependent_pp_optimizer(&self) -> &DataDependentProofPlanOptimizer<B> {
        &self.data_dependent_pp_optimizer
    }

    /// Borrow the context oracles visible to the front-end role.
    pub fn ctx_oracles(&self) -> &CtxOracles<B> {
        &self.ctx_oracles
    }

    /// Borrow the DataFusion session context used for planning and execution.
    pub fn session_ctx(&self) -> &SessionContext {
        &self.session_ctx
    }

    /// Borrow the DataFusion config options used during analysis.
    pub fn config_options(&self) -> &ConfigOptions {
        &self.config_options
    }

    /// Borrow the optimizer context used during logical-plan optimization.
    pub fn optimizer_ctx(&self) -> &OptimizerContext {
        &self.optimizer_ctx
    }

    /// Borrow the observer callback that runs after each optimizer rule.
    pub fn observer(&self) -> fn(&LogicalPlan, &dyn OptimizerRule) {
        self.observer
    }

    /// Parse a SQL query into DataFusion's unoptimized logical plan.
    pub async fn query_to_lp(&self, query: &str) -> LogicalPlan {
        let df = self.session_ctx().sql(query).await.unwrap();
        df.into_unoptimized_plan()
    }

    /// Run the configured analyzer pipeline on a logical plan.
    pub async fn analyze_lp(&self, lp: LogicalPlan) -> LogicalPlan {
        self.analyzer()
            .execute_and_check(lp, self.config_options(), |_plan_after_rule, _rule| {})
            .unwrap()
    }

    /// Run the configured logical optimizer pipeline on an analyzed plan.
    pub async fn optimize_lp(&self, analyzed_lp: LogicalPlan) -> LogicalPlan {
        self.optimizer()
            .optimize(analyzed_lp, self.optimizer_ctx(), self.observer())
            .unwrap()
    }
}

/// Install a query planner that treats selected truth-table extension nodes as
/// physical no-ops so DataFusion can still execute the underlying query.
fn with_noop_extension_support(session_ctx: SessionContext) -> SessionContext {
    let state = session_ctx
        .into_state_builder()
        .with_query_planner(Arc::new(TTQueryPlanner))
        .build();
    SessionContext::new_with_state(state)
}

/// Query planner wrapper that injects a custom extension planner into DataFusion.
#[derive(Debug)]
struct TTQueryPlanner;

#[async_trait]
impl QueryPlanner for TTQueryPlanner {
    async fn create_physical_plan(
        &self,
        logical_plan: &LogicalPlan,
        session_state: &SessionState,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        // The default planner cannot build physical plans for our logical extension
        // nodes, so we install a no-op extension planner for the specific nodes that
        // should behave like passthrough wrappers at execution time.
        let planner =
            DefaultPhysicalPlanner::with_extension_planners(vec![Arc::new(TTNoOpExtensionPlanner)]);
        planner
            .create_physical_plan(logical_plan, session_state)
            .await
    }
}

/// Extension planner that turns selected truth-table logical extension nodes into
/// no-op passthrough execution plans.
#[derive(Debug)]
struct TTNoOpExtensionPlanner;

#[async_trait]
impl ExtensionPlanner for TTNoOpExtensionPlanner {
    async fn plan_extension(
        &self,
        _planner: &dyn PhysicalPlanner,
        node: &dyn UserDefinedLogicalNode,
        _logical_inputs: &[&LogicalPlan],
        physical_inputs: &[Arc<dyn ExecutionPlan>],
        _session_state: &SessionState,
    ) -> DataFusionResult<Option<Arc<dyn ExecutionPlan>>> {
        // Rematerialize and ResultCheck affect proof construction, but they should
        // not change the physical query execution path. Treat them as wrappers over
        // a single input execution plan.
        let is_supported_noop = node.as_any().is::<RematerializeLogicalNode>()
            || node.as_any().is::<ResultCheckLogicalNode>();
        if !is_supported_noop {
            return Ok(None);
        }
        let input = physical_inputs.first().ok_or_else(|| {
            DataFusionError::Plan(format!(
                "{} extension node expected exactly one physical input",
                node.name()
            ))
        })?;
        if physical_inputs.len() != 1 {
            return Err(DataFusionError::Plan(format!(
                "{} extension node expected exactly one physical input, got {}",
                node.name(),
                physical_inputs.len()
            )));
        }
        Ok(Some(Arc::clone(input)))
    }
}

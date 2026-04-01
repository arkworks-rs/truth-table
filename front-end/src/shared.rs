use std::sync::Arc;

use async_trait::async_trait;
use ark_piop::SnarkBackend;
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
use tt_core::irs::nodes::plan::{
    rematerialize::RematerializeLogicalNode,
    result_check::ResultCheckLogicalNode,
};
use tt_core::ctx_oracles::CtxOracles;

pub struct TTSharedConfig<B: SnarkBackend> {
    analyzer: Analyzer,
    optimizer: Optimizer,
    ctx_oracles: CtxOracles<B>,
    session_ctx: SessionContext,
    config_options: ConfigOptions,
    optimizer_ctx: OptimizerContext,
    observer: fn(&LogicalPlan, &dyn OptimizerRule),
}

impl<B: SnarkBackend> TTSharedConfig<B> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        analyzer: Analyzer,
        optimizer: Optimizer,
        ctx_oracles: CtxOracles<B>,
        session_ctx: SessionContext,
        config_options: ConfigOptions,
        optimizer_ctx: OptimizerContext,
        observer: fn(&LogicalPlan, &dyn OptimizerRule),
    ) -> Self {
        Self {
            analyzer,
            optimizer,
            ctx_oracles,
            session_ctx: with_noop_extension_support(session_ctx),
            config_options,
            optimizer_ctx,
            observer,
        }
    }

    pub fn with_defaults(session_ctx: SessionContext) -> Self {
        Self::new(
            Analyzer::with_rules(proof_planner::logical_plan_analyzer::rules()),
            Optimizer::with_rules(proof_planner::logical_plan_optimizer::rules(&session_ctx)),
            CtxOracles::default(),
            session_ctx,
            ConfigOptions::new(),
            OptimizerContext::new(),
            |_plan_after_rule, _rule| {},
        )
    }

    pub fn analyzer(&self) -> &Analyzer {
        &self.analyzer
    }
    pub fn optimizer(&self) -> &Optimizer {
        &self.optimizer
    }
    pub fn ctx_oracles(&self) -> &CtxOracles<B> {
        &self.ctx_oracles
    }
    pub fn session_ctx(&self) -> &SessionContext {
        &self.session_ctx
    }
    pub fn config_options(&self) -> &ConfigOptions {
        &self.config_options
    }
    pub fn optimizer_ctx(&self) -> &OptimizerContext {
        &self.optimizer_ctx
    }
    pub fn observer(&self) -> fn(&LogicalPlan, &dyn OptimizerRule) {
        self.observer
    }

    pub async fn query_to_lp(&self, query: &str) -> LogicalPlan {
        let df = self.session_ctx().sql(query).await.unwrap();
        df.into_unoptimized_plan()
    }

    pub async fn analyze_and_optimize_lp(&self, lp: LogicalPlan) -> LogicalPlan {
        let analyzed_lp = self
            .analyzer()
            .execute_and_check(lp, self.config_options(), |_plan_after_rule, _rule| {})
            .unwrap();

        self.optimizer()
            .optimize(analyzed_lp.clone(), self.optimizer_ctx(), self.observer())
            .unwrap()
    }
}

fn with_noop_extension_support(session_ctx: SessionContext) -> SessionContext {
    let state = session_ctx
        .into_state_builder()
        .with_query_planner(Arc::new(TTQueryPlanner))
        .build();
    SessionContext::new_with_state(state)
}

#[derive(Debug)]
struct TTQueryPlanner;

#[async_trait]
impl QueryPlanner for TTQueryPlanner {
    async fn create_physical_plan(
        &self,
        logical_plan: &LogicalPlan,
        session_state: &SessionState,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        let planner =
            DefaultPhysicalPlanner::with_extension_planners(vec![Arc::new(TTNoOpExtensionPlanner)]);
        planner.create_physical_plan(logical_plan, session_state).await
    }
}

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

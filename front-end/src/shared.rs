use ark_piop::SnarkBackend;
use datafusion::{
    config::ConfigOptions,
    optimizer::{Analyzer, Optimizer, OptimizerContext, OptimizerRule},
    prelude::SessionContext,
};
use datafusion_expr::LogicalPlan;
use truthtable_core::ctx_oracles::CtxOracles;

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
            session_ctx,
            config_options,
            optimizer_ctx,
            observer,
        }
    }

    pub fn with_defaults(session_ctx: SessionContext) -> Self {
        Self::new(
            Analyzer::with_rules(proof_planner::logical_plan_analyzer::rules()),
            Optimizer::with_rules(proof_planner::logical_plan_optimizer::rules()),
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

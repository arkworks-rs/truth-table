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
    compaction::CompactionLogicalNode, result_check::ResultCheckLogicalNode,
};

/// Configuration the prover, the verifier and the data owner share: the
/// DataFusion analyzer and optimizer pipeline, the session context and the
/// context oracles.
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
    /// The session context gets a query planner that treats our logical
    /// extension nodes as no-ops, so DataFusion can execute a plan that
    /// contains them.
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
        let session_ctx = with_noop_extension_support(session_ctx);
        // `tt_prefilter` must resolve on every session: hint-DF execution,
        // data-dependent row counts and codec `ctx.udf(...)` lookups all go
        // through this context.
        session_ctx
            .register_udf(tt_core::irs::nodes::plan::exprs::fp_prefilter::tt_prefilter_udf());
        Self {
            analyzer,
            optimizer,
            pp_optimizer,
            data_dependent_optimizer,
            data_dependent_pp_optimizer,
            ctx_oracles,
            session_ctx,
            config_options,
            optimizer_ctx,
            observer,
        }
    }

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

    pub fn analyzer(&self) -> &Analyzer {
        &self.analyzer
    }

    pub fn optimizer(&self) -> &Optimizer {
        &self.optimizer
    }

    pub fn pp_optimizer(&self) -> &ProofPlanOptimizer<B> {
        &self.pp_optimizer
    }

    /// Produces the hints the prover ships with the proof for the verifier to
    /// replay.
    pub fn data_dependent_optimizer(&self) -> &DataDependentOptimizer {
        &self.data_dependent_optimizer
    }

    /// Its default rule list is empty.
    pub fn data_dependent_pp_optimizer(&self) -> &DataDependentProofPlanOptimizer<B> {
        &self.data_dependent_pp_optimizer
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

    /// Runs after each optimizer rule.
    pub fn observer(&self) -> fn(&LogicalPlan, &dyn OptimizerRule) {
        self.observer
    }

    /// The unoptimized logical plan of `query`, with unique output names.
    pub async fn query_to_lp(&self, query: &str) -> LogicalPlan {
        let df = self.session_ctx().sql(query).await.unwrap();
        with_unique_output_names(df.into_unoptimized_plan())
    }

    pub async fn analyze_lp(&self, lp: LogicalPlan) -> LogicalPlan {
        self.analyzer()
            .execute_and_check(lp, self.config_options(), |_plan_after_rule, _rule| {})
            .unwrap()
    }

    pub async fn optimize_lp(&self, analyzed_lp: LogicalPlan) -> LogicalPlan {
        let optimized = self
            .optimizer()
            .optimize(analyzed_lp, self.optimizer_ctx(), self.observer())
            .unwrap();
        // Deterministic post-pass, identical on prover and verifier: insert
        // fingerprint pre-filters in front of LIKE filters. Inside the rule
        // list, MergeConsecutiveFilters/PushDownFilter would fold the inserted
        // filter back into the LIKE filter.
        proof_planner::lp_optimizer::insert_like_prefilters(optimized)
            .expect("LIKE pre-filter insertion should succeed")
    }
}

/// Renames repeated output column names so every result column has its own
/// name. SQL allows repeats (`SELECT l1.x, l2.x ...`), but the result table
/// is matched column by column by name, and a table keyed by field would
/// collapse the repeats into one column. The first occurrence keeps its name
/// and later ones get the lowest free `name_<n>`, n >= 2. Prover and verifier
/// both plan through this function, so both see the same names.
fn with_unique_output_names(plan: LogicalPlan) -> LogicalPlan {
    use datafusion_common::Column;
    use datafusion_expr::{Expr, LogicalPlanBuilder};
    use std::collections::BTreeSet;

    let schema = plan.schema().clone();
    let names: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
    let mut taken: BTreeSet<String> = names.iter().map(|name| name.to_string()).collect();
    if taken.len() == names.len() {
        return plan;
    }
    let mut seen = BTreeSet::new();
    let exprs = schema
        .iter()
        .map(|(qualifier, field)| {
            let column = Expr::Column(Column::new(qualifier.cloned(), field.name()));
            if seen.insert(field.name().clone()) {
                return column;
            }
            let renamed = (2..)
                .map(|n| format!("{}_{n}", field.name()))
                .find(|candidate| !taken.contains(candidate))
                .expect("an unused column name exists");
            taken.insert(renamed.clone());
            column.alias(renamed)
        })
        .collect::<Vec<_>>();
    LogicalPlanBuilder::from(plan)
        .project(exprs)
        .and_then(|builder| builder.build())
        .expect("renaming repeated output columns should succeed")
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

#[derive(Debug)]
struct TTQueryPlanner;

#[async_trait]
impl QueryPlanner for TTQueryPlanner {
    async fn create_physical_plan(
        &self,
        logical_plan: &LogicalPlan,
        session_state: &SessionState,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        // The default planner cannot build physical plans for our logical
        // extension nodes.
        let planner =
            DefaultPhysicalPlanner::with_extension_planners(vec![Arc::new(TTNoOpExtensionPlanner)]);
        planner
            .create_physical_plan(logical_plan, session_state)
            .await
    }
}

/// Turns the truth-table extension nodes that only matter to the proof into
/// passthrough execution plans.
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
        // Compaction and ResultCheck affect proof construction, not query
        // execution: each is a wrapper over a single input execution plan.
        let is_supported_noop = node.as_any().is::<CompactionLogicalNode>()
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

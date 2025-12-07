use std::sync::Arc;

use ark_piop::{prover::ArgProver, SnarkBackend};
use datafusion::{
    arrow::datatypes::Schema,
    config::ConfigOptions,
    datasource::MemTable,
    optimizer::{Analyzer, Optimizer, OptimizerContext, OptimizerRule},
    prelude::SessionContext,
};
use datafusion_common::DFSchema;
use datafusion_expr::LogicalPlan;
use truthtable_core::{
    ctx_oracles::CtxOracles,
    errors::TTResult,
    irs::{ir::Ir, nodes::Node, tree::Tree},
    prover::{
        irs::{MaterializedIr, VirtualizedIr},
        passes::{
            arithmetization::ArithmetizationPass, materialization::MaterializationPass,
            planning::PlanningPass, tracking::TrackingPass, virtualization::VirtualizationPass,
        },
        payloads::{EmptyPayload, PayloadStructure},
    },
};

use crate::structs::TTProof;

pub struct TTProverConfig<B: SnarkBackend> {
    analyzer: Analyzer,
    optimizer: Optimizer,
    ctx_oracles: CtxOracles<B>,
    session_ctx: SessionContext,
    config_options: ConfigOptions,
    optimizer_ctx: OptimizerContext,
    observer: fn(&LogicalPlan, &dyn OptimizerRule),
    arg_prover: ArgProver<B>,
}

impl<B: SnarkBackend> TTProverConfig<B> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        analyzer: Analyzer,
        optimizer: Optimizer,
        ctx_oracles: CtxOracles<B>,
        session_ctx: SessionContext,
        config_options: ConfigOptions,
        optimizer_ctx: OptimizerContext,
        observer: fn(&LogicalPlan, &dyn OptimizerRule),
        arg_prover: ArgProver<B>,
    ) -> Self {
        Self {
            analyzer,
            optimizer,
            ctx_oracles,
            session_ctx,
            config_options,
            optimizer_ctx,
            observer,
            arg_prover,
        }
    }

    pub fn with_defaults(
        session_ctx: SessionContext,
        arg_prover: ArgProver<B>,
    ) -> Self {
        Self::new(
            Analyzer::new(),
            Optimizer::new(),
            CtxOracles::default(),
            session_ctx,
            ConfigOptions::new(),
            OptimizerContext::new(),
            |_plan_after_rule, _rule| {},
            arg_prover,
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
    pub fn planning_pass(&self) -> PlanningPass<B> {
        PlanningPass::new()
    }
    pub fn materialization_pass(&self) -> MaterializationPass<B> {
        MaterializationPass::new()
    }
    pub fn arithmetization_pass(&self) -> ArithmetizationPass<B> {
        ArithmetizationPass::new()
    }
    pub fn tracking_pass(&self) -> TrackingPass<B> {
        TrackingPass::new(self.arg_prover().clone())
    }
    pub fn arg_prover(&self) -> &ArgProver<B> {
        &self.arg_prover
    }
}

/// Prover configuration that bundles planner rules and context oracles.
pub struct TTProver<B: SnarkBackend> {
    config: TTProverConfig<B>,
}

impl<B: SnarkBackend> TTProver<B> {
    pub fn new(config: TTProverConfig<B>) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &TTProverConfig<B> {
        &self.config
    }

    pub async fn prove(&self, query: &str) -> TTResult<(Arc<MemTable>, TTProof<B>)> {
        let initial_lp = self.query_to_lp(query).await;
        let analyzed_and_optimized_lp = self.analyze_and_optimize_lp(initial_lp).await;
        let tree: Tree<B> = Tree::from_logical_plan(&analyzed_and_optimized_lp);
        let materialized_ir = self.perform_primary_passes(tree).await;
        let output_memtable = self.extract_output_memtable(&materialized_ir).await?;
        self.perform_secondary_passes(materialized_ir).await;
        let mut arg_prover = self.config().arg_prover.clone();
        let arg_proof = arg_prover.build_proof().unwrap();
        let tt_proof = TTProof::new(arg_proof);
        Ok((output_memtable, tt_proof))
    }

    async fn query_to_lp(&self, query: &str) -> LogicalPlan {
        let df = self.config.session_ctx().sql(query).await.unwrap();
        df.into_unoptimized_plan()
    }

    async fn analyze_and_optimize_lp(&self, lp: LogicalPlan) -> LogicalPlan {
        let analyzed_lp = self
            .config()
            .analyzer
            .execute_and_check(
                lp,
                &self.config().config_options,
                |_plan_after_rule, _rule| {},
            )
            .unwrap();

        self.config()
            .optimizer
            .optimize(
                analyzed_lp.clone(),
                &self.config().optimizer_ctx,
                self.config().observer,
            )
            .unwrap()
    }
    async fn perform_primary_passes(&self, tree: Tree<B>) -> MaterializedIr<B> {
        let initial_ir = Ir::<B, EmptyPayload>::new_empty(tree);
        let planned_ir = initial_ir.apply_local_pass_parallel(&self.config().planning_pass());
        planned_ir.apply_local_pass_parallel(&self.config().materialization_pass())
    }
    async fn perform_secondary_passes(&self, materialized_ir: MaterializedIr<B>) {
        let arithmetized_ir =
            materialized_ir.apply_local_pass_parallel(&self.config().arithmetization_pass());
        let tracked_ir =
            arithmetized_ir.apply_local_pass_sequential(&self.config().tracking_pass());
        let virtualization_pass = VirtualizationPass::<B>::new(&tracked_ir);
        tracked_ir.apply_local_pass_sequential(&virtualization_pass);
    }
    async fn extract_output_memtable(
        &self,
        materialized_ir: &MaterializedIr<B>,
    ) -> TTResult<Arc<MemTable>> {
        let root_id = materialized_ir.tree().root().id();
        let payload = materialized_ir
            .payloads()
            .get(&root_id)
            .cloned()
            .flatten();

        if let Some(materialized_table) = payload {
            let mem_table = match materialized_table {
                PayloadStructure::PlanPayload(table) => table.mem_table_arc(),
                _ => panic!("expected plan payload at root node"),
            };
            return Ok(mem_table);
        }

        let output_hint_df = match materialized_ir.tree().root().as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("expected plan node at root"),
        };
        let df = output_hint_df.data_frame().clone();
        let df_schema = df.schema().clone();
        let batches = df
            .collect()
            .await
            .expect("output dataframe collection should succeed");
        let arrow_schema: Schema =
            <DFSchema as AsRef<Schema>>::as_ref(&df_schema).clone();
        let mem_table = MemTable::try_new(Arc::new(arrow_schema), vec![batches])
            .expect("memtable creation should succeed");

        Ok(Arc::new(mem_table))
    }
}

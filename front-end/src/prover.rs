use std::sync::Arc;

use ark_piop::{
    pcs::PCS,
    prover::{structs::proof, ArgProver},
    SnarkBackend,
};
use datafusion::{arrow::datatypes::Schema, datasource::MemTable};
use datafusion_common::DFSchema;
use indexmap::IndexMap;
use proof_planner::proof_plan_optimizer::{rules as proof_plan_rules, ProofPlanOptimizer};
use tracing::debug;
#[cfg(feature = "honest-prover")]
use tt_core::prover::passes::honest_prover::HonestProverPass;
use tt_core::{
    ctx_oracles::CtxOracles,
    errors::TTResult,
    irs::{
        nodes::{Node, NodeId},
        payloads::PayloadStructure,
        shared_ir::{EmptyIr, GadgetPlannedIr, OutputPlannedIr},
        shared_passes::{GadgetPlanningPass, OutputPlanningPass},
        tree::Tree,
    },
    prover::{
        irs::{
            ArithmetizedIr, CommittedIr, GadgetReadyIr as ProverGadgetReadyIr, MaterializedIr,
            TrackedIr, VirtualizedIr as ProverVirtualizedIr,
        },
        passes::{
            arithmetization::ArithmetizationPass, commitment::CommitmentPass,
            gadget_initialization::GadgetInitializationPass, materialization::MaterializationPass,
            proving::ProvingPass, tracking::TrackingPass, virtualization::VirtualizationPass,
        },
        payloads::ArithPayload,
    },
};

use crate::{shared::TTSharedConfig, structs::TTProof};

pub struct ProverIrStages<B: SnarkBackend> {
    pub initial: EmptyIr<B>,
    pub output_planned: OutputPlannedIr<B>,
    pub gadget_planned: GadgetPlannedIr<B>,
    pub materialized: MaterializedIr<B>,
    pub arithmetized: ArithmetizedIr<B>,
    pub committed: CommittedIr<B>,
    pub tracked: TrackedIr<B>,
    pub virtualized: ProverVirtualizedIr<B>,
    pub gadget_ready: ProverGadgetReadyIr<B>,
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
    pub fn output_planning_pass(&self) -> OutputPlanningPass<B> {
        OutputPlanningPass::new()
    }
    pub fn gadget_planning_pass(&self, planned_ir: &OutputPlannedIr<B>) -> GadgetPlanningPass<B> {
        GadgetPlanningPass::new(planned_ir)
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
        CommitmentPass::new(mv_pcs_param, ctx_oracles)
    }
    pub fn tracking_pass(
        &self,
        arg_prover: ArgProver<B>,
        arith_payloads: IndexMap<NodeId, Option<ArithPayload<B::F>>>,
    ) -> TrackingPass<B> {
        TrackingPass::new(arg_prover, arith_payloads)
    }
}

impl<B: SnarkBackend> Default for TTProverConfig<B> {
    fn default() -> Self {
        Self::new()
    }
}

/// Prover configuration that bundles planner rules and context oracles.
pub struct TTProver<B: SnarkBackend> {
    prover_config: TTProverConfig<B>,
    shared_config: TTSharedConfig<B>,
    arg_prover: ArgProver<B>,
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
            arg_prover,
        }
    }

    pub fn prover_config(&self) -> &TTProverConfig<B> {
        &self.prover_config
    }
    pub fn shared_config(&self) -> &TTSharedConfig<B> {
        &self.shared_config
    }
    pub fn arg_prover(&self) -> &ArgProver<B> {
        &self.arg_prover
    }

    pub async fn prove(&self, query: &str) -> TTResult<(Arc<MemTable>, TTProof<B>)> {
        let (stages, mut arg_prover) = self.build_ir_stages(query).await?;
        let output_memtable = self.extract_output_memtable(&stages.materialized).await?;
        let arg_proof = arg_prover.build_proof().unwrap();
        let optimized_ir = EmptyIr::<B>::new_empty(stages.initial.tree().clone());
        let tt_proof = TTProof::new(arg_proof, optimized_ir);
        Ok((output_memtable, tt_proof))
    }

    pub async fn build_ir_stages(
        &self,
        query: &str,
    ) -> TTResult<(ProverIrStages<B>, ArgProver<B>)> {
        let initial_lp = self.shared_config().query_to_lp(query).await;
        debug!("Initial Logical plan{}", initial_lp.display_graphviz());
        let analyzed_and_optimized_lp = self
            .shared_config()
            .analyze_and_optimize_lp(initial_lp)
            .await;

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
        let output_planned_ir = optimized_initial_ir
            .apply_local_pass_parallel(&self.prover_config().output_planning_pass());
        debug!(
            "output planned ir:\n{}",
            output_planned_ir.display_graphviz(true)
        );
        let gadget_planned_ir = output_planned_ir.apply_local_pass_sequential(
            &self
                .prover_config()
                .gadget_planning_pass(&output_planned_ir),
        );
        debug!(
            "gadget planned ir:\n{}",
            gadget_planned_ir.display_graphviz(true)
        );
        let materialized_ir = gadget_planned_ir
            .apply_local_pass_parallel(&self.prover_config().materialization_pass());
        debug!(
            "materialized ir:\n{}",
            materialized_ir.display_graphviz(true)
        );
        let arithmetized_ir =
            materialized_ir.apply_local_pass_parallel(&self.prover_config().arithmetization_pass());
        debug!(
            "arithmetized ir:\n{}",
            arithmetized_ir.display_graphviz(true)
        );

        let arg_prover = self.arg_prover().clone();
        let committed_ir =
            arithmetized_ir.apply_local_pass_parallel(&self.prover_config().commitment_pass(
                arg_prover.mv_pcs_prover_param(),
                self.shared_config().ctx_oracles().clone(),
            ));
        // debug!("committed ir:\n{}", committed_ir.display_graphviz(true));

        let tracked_ir = committed_ir.apply_local_pass_sequential(
            &self
                .prover_config()
                .tracking_pass(arg_prover.clone(), arithmetized_ir.payloads().clone()),
        );
        debug!("tracked ir:\n{}", tracked_ir.display_graphviz(true));

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
        debug!(
            "gadget ready ir:\n{}",
            gadget_ready_ir.display_graphviz(true)
        );
        let proving_ir_view = ProverGadgetReadyIr::new(
            gadget_ready_ir.tree().clone(),
            gadget_ready_ir.payloads().clone(),
        );
        #[cfg(feature = "honest-prover")]
        {
            // Run the honest prover pass only when the feature is enabled.
            let honest_ir_view = ProverGadgetReadyIr::new(
                gadget_ready_ir.tree().clone(),
                gadget_ready_ir.payloads().clone(),
            );
            let honest_prover_pass = HonestProverPass::<B>::new(arg_prover.clone(), honest_ir_view);
            let _honest_ir = gadget_ready_ir.apply_local_pass_sequential(&honest_prover_pass);
            honest_prover_pass.take_result()?;
        }
        let proving_pass = ProvingPass::<B>::new(arg_prover.clone(), proving_ir_view);
        let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&proving_pass);
        proving_pass.take_result()?;

        Ok((
            ProverIrStages {
                initial: optimized_initial_ir,
                output_planned: output_planned_ir,
                gadget_planned: gadget_planned_ir,
                materialized: materialized_ir,
                arithmetized: arithmetized_ir,
                committed: committed_ir,
                tracked: tracked_ir,
                virtualized: virtualized_ir,
                gadget_ready: gadget_ready_ir,
            },
            arg_prover,
        ))
    }

    async fn extract_output_memtable(
        &self,
        materialized_ir: &MaterializedIr<B>,
    ) -> TTResult<Arc<MemTable>> {
        let root_id = materialized_ir.tree().root().id();
        let payload = materialized_ir.payloads().get(&root_id).cloned().flatten();

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
        let arrow_schema: Schema = <DFSchema as AsRef<Schema>>::as_ref(&df_schema).clone();
        let mem_table = MemTable::try_new(Arc::new(arrow_schema), vec![batches])
            .expect("memtable creation should succeed");

        Ok(Arc::new(mem_table))
    }
}

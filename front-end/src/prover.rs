use std::sync::Arc;

use arithmetic::table::TrackedTable;
use ark_piop::{
    pcs::PCS,
    prover::ArgProver,
    SnarkBackend,
};
use datafusion::{arrow::datatypes::Schema, datasource::MemTable};
use datafusion_common::{DFSchema, DataFusionError};
use indexmap::IndexMap;
use proof_planner::proof_plan_optimizer::{rules as proof_plan_rules, ProofPlanOptimizer};
use tracing::debug;
#[cfg(feature = "honest-prover")]
use tt_core::prover::passes::honest_prover::HonestProverPass;
use tt_core::{
    ctx_oracles::CtxOracles,
    errors::TTResult,
    irs::{
        nodes::{IsNode, IsProverPlanNode, Node, NodeId},
        payloads::PayloadStructure,
        shared_ir::{EmptyIr, OutputPlannedIr},
        tree::Tree,
    },
    prover::{
        irs::{GadgetReadyIr as ProverGadgetReadyIr, MaterializedIr, VirtualizedIr as ProverVirtualizedIr},
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
        CommitmentPass::new(mv_pcs_param, ctx_oracles)
    }
    pub fn tracking_pass<'a>(
        &self,
        arg_prover: ArgProver<B>,
        arith_payloads: &'a IndexMap<NodeId, Option<ArithPayload<B::F>>>,
    ) -> TrackingPass<'a, B> {
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
        let (output_memtable, _table_scan, tt_proof) = self.prove_internal(query, true, false).await?;
        Ok((
            output_memtable.expect("output memtable should be present for prove()"),
            tt_proof,
        ))
    }

    pub async fn prove_with_table_scan(
        &self,
        query: &str,
    ) -> TTResult<(TrackedTable<B>, TTProof<B>)> {
        let (_output_memtable, table_scan, tt_proof) = self.prove_internal(query, false, true).await?;
        Ok((
            table_scan.expect("table scan payload should be present for commit proofs"),
            tt_proof,
        ))
    }

    async fn prove_internal(
        &self,
        query: &str,
        capture_output_memtable: bool,
        capture_table_scan: bool,
    ) -> TTResult<(Option<Arc<MemTable>>, Option<TrackedTable<B>>, TTProof<B>)> {
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
        let optimized_tree = optimized_initial_ir.tree().clone();
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
        drop(output_planned_ir);
        debug!(
            "gadget planned ir:\n{}",
            gadget_planned_ir.display_graphviz(true)
        );
        let materialized_ir = gadget_planned_ir
            .apply_local_pass_parallel(&self.prover_config().materialization_pass());
        drop(gadget_planned_ir);
        debug!(
            "materialized ir:\n{}",
            materialized_ir.display_graphviz(true)
        );

        let output_memtable = if capture_output_memtable {
            Some(self.extract_output_memtable(&materialized_ir).await?)
        } else {
            None
        };

        let arithmetized_ir =
            materialized_ir.apply_local_pass_parallel(&self.prover_config().arithmetization_pass());
        drop(materialized_ir);
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
                .tracking_pass(arg_prover.clone(), arithmetized_ir.payloads()),
        );
        drop(arithmetized_ir);
        drop(committed_ir);
        debug!("tracked ir:\n{}", tracked_ir.display_graphviz(true));

        let table_scan = if capture_table_scan {
            Some(Self::table_scan_payload(&tracked_ir)?)
        } else {
            None
        };

        let virtualization_pass = VirtualizationPass::<B>::new(&tracked_ir);
        let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);
        drop(tracked_ir);
        debug!("virtualized ir:\n{}", virtualized_ir.display_graphviz(true));
        let gadget_ir_view = ProverVirtualizedIr::new(
            virtualized_ir.tree().clone(),
            virtualized_ir.payloads().clone(),
        );
        let gadget_initialization_pass =
            GadgetInitializationPass::<B>::new(gadget_ir_view, arg_prover.clone());
        let gadget_ready_ir =
            virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);
        drop(virtualized_ir);
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
            let honest_prover_pass =
                HonestProverPass::<B>::new(arg_prover.deep_copy(), honest_ir_view);
            let _honest_ir = gadget_ready_ir.apply_local_pass_sequential(&honest_prover_pass);
            honest_prover_pass.take_result()?;
        }
        let proving_pass = ProvingPass::<B>::new(arg_prover.clone(), proving_ir_view);
        let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&proving_pass);
        drop(gadget_ready_ir);
        proving_pass.take_result()?;
        let mut arg_prover = arg_prover;
        let arg_proof = arg_prover.build_proof().unwrap();
        let optimized_ir = EmptyIr::<B>::new_empty(optimized_tree);
        let tt_proof = TTProof::new(arg_proof, optimized_ir);
        Ok((output_memtable, table_scan, tt_proof))
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

    fn table_scan_payload(tracked_ir: &tt_core::prover::irs::TrackedIr<B>) -> TTResult<TrackedTable<B>> {
        for (node_id, node) in tracked_ir.tree().arena() {
            if node.name() != "TableScan" {
                continue;
            }

            let payload = tracked_ir
                .payloads()
                .get(node_id)
                .and_then(|payload| payload.clone())
                .and_then(|payload| match payload {
                    PayloadStructure::PlanPayload(table) => Some(table),
                    _ => None,
                });

            if let Some(table) = payload {
                return Ok(table);
            }
        }

        Err(DataFusionError::Internal("table scan payload not found".to_string()).into())
    }
}

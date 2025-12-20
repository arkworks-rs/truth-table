use std::sync::Arc;

use ark_piop::{prover::ArgProver, SnarkBackend};
use datafusion::{arrow::datatypes::Schema, datasource::MemTable};
use datafusion_common::DFSchema;
use truthtable_core::{
    errors::TTResult,
    irs::{
        ir::Ir,
        nodes::Node,
        payloads::{EmptyPayload, PayloadStructure},
        shared_passes::PlanningPass,
        tree::Tree,
    },
    prover::{
        irs::MaterializedIr,
        passes::{
            arithmetization::ArithmetizationPass, materialization::MaterializationPass,
            tracking::TrackingPass, virtualization::VirtualizationPass,
        },
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
    pub fn planning_pass(&self) -> PlanningPass<B> {
        PlanningPass::new()
    }
    pub fn materialization_pass(&self) -> MaterializationPass<B> {
        MaterializationPass::new()
    }
    pub fn arithmetization_pass(&self) -> ArithmetizationPass<B> {
        ArithmetizationPass::new()
    }
    pub fn tracking_pass(&self, arg_prover: ArgProver<B>) -> TrackingPass<B> {
        TrackingPass::new(arg_prover)
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
        let initial_lp = self.shared_config().query_to_lp(query).await;
        let analyzed_and_optimized_lp = self
            .shared_config()
            .analyze_and_optimize_lp(initial_lp)
            .await;
        let tree: Tree<B> = Tree::from_logical_plan(&analyzed_and_optimized_lp);
        let materialized_ir = self.perform_primary_passes(tree).await;
        let output_memtable = self.extract_output_memtable(&materialized_ir).await?;
        self.perform_secondary_passes(materialized_ir).await;
        let mut arg_prover = self.arg_prover().clone();
        let arg_proof = arg_prover.build_proof().unwrap();
        let tt_proof = TTProof::new(arg_proof);
        Ok((output_memtable, tt_proof))
    }

    async fn perform_primary_passes(&self, tree: Tree<B>) -> MaterializedIr<B> {
        let initial_ir = Ir::<B, EmptyPayload>::new_empty(tree);
        let planned_ir =
            initial_ir.apply_local_pass_parallel(&self.prover_config().planning_pass());
        planned_ir.apply_local_pass_parallel(&self.prover_config().materialization_pass())
    }
    async fn perform_secondary_passes(&self, materialized_ir: MaterializedIr<B>) {
        let arithmetized_ir =
            materialized_ir.apply_local_pass_parallel(&self.prover_config().arithmetization_pass());
        let tracked_ir = arithmetized_ir.apply_local_pass_sequential(
            &self
                .prover_config()
                .tracking_pass(self.arg_prover().clone()),
        );
        let virtualization_pass = VirtualizationPass::<B>::new(&tracked_ir);
        tracked_ir.apply_local_pass_sequential(&virtualization_pass);
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

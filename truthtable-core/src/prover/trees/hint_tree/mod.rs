use crate::{
    proof_nodes::{HintDF, prover::ProverPlanNode},
    prover::trees::proof_tree::ProverProofTree,
    tree::{NodeId, ProverPlanTree},
};
// pub mod display;
// #[cfg(test)]
// pub mod tests;
use futures::future::try_join_all;
use indexmap::IndexMap;
use std::{fmt, sync::Arc};

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{
    arrow::record_batch::RecordBatch,
    datasource::{MemTable, TableProvider},
    error::{DataFusionError, Result as DFResult},
    prelude::SessionContext,
};

pub struct HintedProverPlanNode<F, MvPCS, UvPCS> {
    inner: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    hints: IndexMap<String, MemTable>,
}

impl<F, MvPCS, UvPCS> ProverPlanNode<F, MvPCS, UvPCS> for HintedProverPlanNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    fn display(&self) -> String {
        let base_display = self.inner.display();
        if self.hints.is_empty() {
            return base_display;
        }
        let mut hint_parts = Vec::with_capacity(self.hints.len());
        for (name, table) in &self.hints {
            let stats = TableProvider::statistics(table).unwrap();
            let rows = stats.num_rows;
            let columns = table
                .schema()
                .fields()
                .iter()
                .map(|f| f.name().as_str().to_owned())
                .collect::<Vec<_>>()
                .join(", ");
            hint_parts.push(format!("{name}={rows} rows ({columns})"));
        }
        format!("{base_display} [hints: {}]", hint_parts.join(", "))
    }

    fn gadget_tree(&self) -> crate::prover::trees::gadget_tree::GadgetTree<F, MvPCS, UvPCS> {
        todo!()
    }

    fn node_id(&self) -> NodeId {
        self.inner.node_id()
    }

    fn children(&self) -> Vec<Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>> {
        self.inner.children()
    }

    fn output(&self, proof_tree: &ProverProofTree<F, MvPCS, UvPCS>) -> HintDF {
        self.inner.output(proof_tree)
    }

    fn ctx_lp_node(
        &self,
        proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>> {
        self.inner.ctx_lp_node(proof_tree)
    }

    fn arithmetic_post_process(&self) {
        self.inner.arithmetic_post_process()
    }

    fn add_virtual_witness(&self, prover: &mut ark_piop::prover::ArgProver<F, MvPCS, UvPCS>) {
        self.inner.add_virtual_witness(prover)
    }

    fn cost(
        &self,
        statistics: datafusion_common::Statistics,
        schema: datafusion::arrow::datatypes::SchemaRef,
    ) -> crate::proof_nodes::cost::ProvingCost {
        self.inner.cost(statistics, schema)
    }
}

pub struct ProverHintTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    arena: IndexMap<NodeId, Arc<HintedProverPlanNode<F, MvPCS, UvPCS>>>,
    root: Arc<HintedProverPlanNode<F, MvPCS, UvPCS>>,
    proof_tree: ProverProofTree<F, MvPCS, UvPCS>,
    hint_batches: IndexMap<NodeId, IndexMap<String, Vec<RecordBatch>>>,
}

impl<F, MvPCS, UvPCS> fmt::Debug for ProverHintTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_graphviz())
    }
}

impl<F, MvPCS, UvPCS> fmt::Display for ProverHintTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let node_count = self.arena.len();
        let root_label = self.root.name();
        write!(
            f,
            "ProverHintTree {{ nodes: {}, root: {} }}",
            node_count, root_label
        )
    }
}

impl<F, MvPCS, UvPCS> ProverPlanTree<F, MvPCS, UvPCS> for ProverHintTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    type Node = HintedProverPlanNode<F, MvPCS, UvPCS>;
    fn arena(&self) -> &IndexMap<NodeId, Arc<HintedProverPlanNode<F, MvPCS, UvPCS>>> {
        &self.arena
    }

    fn root(&self) -> &Arc<HintedProverPlanNode<F, MvPCS, UvPCS>> {
        &self.root
    }

    fn get_node(&self, node_id: &NodeId) -> Option<&Arc<HintedProverPlanNode<F, MvPCS, UvPCS>>> {
        self.arena.get(node_id)
    }
}

impl<F, MvPCS, UvPCS> ProverHintTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    pub async fn from_proof_tree(
        _ctx: &SessionContext,
        proof_tree: ProverProofTree<F, MvPCS, UvPCS>,
    ) -> DFResult<Self> {
        let root_id = proof_tree.root().node_id();

        // For each node: execute its gadget hints, materialize into record batches,
        // wrap as MemTables, and collect both tables and raw batches.
        let node_tasks = proof_tree.arena().iter().map(|(node_id, node)| {
            let node_id = node_id.clone();
            let node = Arc::clone(node);
            async move {
                let hints = node.gadget_tree().hints();
                let hint_tasks = hints.into_iter().map(|(label, hint_df)| {
                    let df = hint_df.data_frame().clone();
                    async move {
                        // Collect DataFrame to batches; DataFusion returns DFSchema so grab inner SchemaRef.
                        let schema = df.schema().inner().clone();
                        let batches: Vec<RecordBatch> = df.collect().await?;
                        let mem_table = MemTable::try_new(schema, vec![batches.clone()])?;
                        Ok::<(String, MemTable, Vec<RecordBatch>), DataFusionError>((
                            label, mem_table, batches,
                        ))
                    }
                });

                let hint_results: Vec<(String, MemTable, Vec<RecordBatch>)> =
                    try_join_all(hint_tasks).await?;
                // Preserve table providers and batches keyed by label.
                let mut tables = IndexMap::with_capacity(hint_results.len());
                let mut batches_by_label = IndexMap::with_capacity(hint_results.len());
                for (label, table, batches) in hint_results {
                    batches_by_label.insert(label.clone(), batches);
                    tables.insert(label, table);
                }

                Ok::<
                    (
                        NodeId,
                        Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
                        IndexMap<String, MemTable>,
                        IndexMap<String, Vec<RecordBatch>>,
                    ),
                    DataFusionError,
                >((node_id, node, tables, batches_by_label))
            }
        });

        // Finish assembling the hinted plan tree plus batch map.
        let node_results: Vec<(
            NodeId,
            Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
            IndexMap<String, MemTable>,
            IndexMap<String, Vec<RecordBatch>>,
        )> = try_join_all(node_tasks).await?;
        let mut arena = IndexMap::with_capacity(node_results.len());
        let mut hint_batches = IndexMap::with_capacity(node_results.len());
        let mut root: Option<Arc<HintedProverPlanNode<F, MvPCS, UvPCS>>> = None;

        for (node_id, node, tables, batches) in node_results {
            let hinted = Arc::new(HintedProverPlanNode {
                inner: node,
                hints: tables,
            });
            if node_id == root_id {
                root = Some(Arc::clone(&hinted));
            }
            hint_batches.insert(node_id.clone(), batches);
            arena.insert(node_id, hinted);
        }

        let root = root.ok_or_else(|| {
            DataFusionError::Execution("failed to locate root node for hint tree".to_string())
        })?;

        Ok(Self {
            arena,
            root,
            proof_tree,
            hint_batches,
        })
    }

    pub fn batches_for(&self, node_id: &NodeId, label: &str) -> Option<&Vec<RecordBatch>> {
        self.hint_batches
            .get(node_id)
            .and_then(|by_label| by_label.get(label))
    }

    pub fn into_parts(
        self,
    ) -> (
        ProverProofTree<F, MvPCS, UvPCS>,
        IndexMap<NodeId, IndexMap<String, Vec<RecordBatch>>>,
    ) {
        (self.proof_tree, self.hint_batches)
    }
}

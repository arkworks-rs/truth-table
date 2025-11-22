use crate::{
    proof_nodes::{HintDF, prover::ProverPlanNode},
    prover::trees::{gadget_tree::GadgetForest, proof_tree::ProverProofTree},
    tree::{NodeId, ProverPlanTree},
};
// pub mod display;
// #[cfg(test)]
// pub mod tests;
use indexmap::IndexMap;
use std::{fmt, sync::Arc};

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::datasource::{MemTable, TableProvider};

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

    fn gadget_forest(&self) -> GadgetForest<F, MvPCS, UvPCS> {
        self.inner.gadget_forest()
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

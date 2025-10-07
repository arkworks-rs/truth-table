use crate::{
    id::NodeId,
    prover::trees::{proof_tree::ProverProofTree, tracked_tree::ProverTrackedTree},
};
pub mod display;

#[cfg(test)]
mod tests;

use std::{collections::HashMap, fmt};

use indexmap::IndexMap;

use arithmetic::table::TrackedTable;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    piop::PIOP,
    prover::Prover,
};
use tracing::instrument;

/// Virtualized tables indexed by proof-plan node identifier.
pub struct ProverPIOPTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    tracked_tables: IndexMap<NodeId, HashMap<String, TrackedTable<F, MvPCS, UvPCS>>>,
    inner_proof_tree: ProverProofTree<F, MvPCS, UvPCS>,
}

impl<F, MvPCS, UvPCS> fmt::Debug for ProverPIOPTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProverPIOPTree")
            .field("num_nodes", &self.tracked_tables.len())
            .field(
                "nodes",
                &VirtualNodesDebug {
                    inner: &self.tracked_tables,
                },
            )
            .finish()
    }
}

impl<F, MvPCS, UvPCS> ProverPIOPTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub fn new(
        proof_tree: ProverProofTree<F, MvPCS, UvPCS>,
        tracked_tables: IndexMap<NodeId, HashMap<String, TrackedTable<F, MvPCS, UvPCS>>>,
    ) -> Self {
        Self {
            tracked_tables,
            inner_proof_tree: proof_tree,
        }
    }

    pub fn len(&self) -> usize {
        self.tracked_tables.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tracked_tables.is_empty()
    }

    pub fn tracked_tables(
        &self,
    ) -> &IndexMap<NodeId, HashMap<String, TrackedTable<F, MvPCS, UvPCS>>> {
        &self.tracked_tables
    }

    pub fn tables_for(
        &self,
        node_id: &NodeId,
    ) -> Option<&HashMap<String, TrackedTable<F, MvPCS, UvPCS>>> {
        self.tracked_tables.get(node_id)
    }

    pub fn proof_tree(&self) -> &ProverProofTree<F, MvPCS, UvPCS> {
        &self.inner_proof_tree
    }

    pub fn display_graphviz(&self) -> display::DisplayableProverPIOPTree<'_, F, MvPCS, UvPCS> {
        display::DisplayableProverPIOPTree::new(self)
    }

    pub fn add_table(
        &mut self,
        node_id: NodeId,
        label: String,
        table: TrackedTable<F, MvPCS, UvPCS>,
    ) {
        self.tracked_tables
            .entry(node_id)
            .or_default()
            .insert(label, table);
    }

    pub fn tracked_table(
        &self,
        node_id: &NodeId,
        label: &str,
    ) -> Option<&TrackedTable<F, MvPCS, UvPCS>> {
        self.tracked_tables
            .get(node_id)
            .and_then(|by_label| by_label.get(label))
    }

    /// Build a virtualized plan from an arithmetized plan.
    #[instrument(level = "debug", skip_all)]
    pub fn from_tracked_plan(
        arith_plan: ProverTrackedTree<F, MvPCS, UvPCS>,
        prover: &mut Prover<F, MvPCS, UvPCS>,
    ) -> Self {
        let (proof_tree, tables_by_node) = arith_plan.into_parts();
        // TODO: See if we can avoid these clones, specially cloning the tables_by_node
        let mut piop_tree = ProverPIOPTree::new(proof_tree.clone(), tables_by_node.clone());
        let flattened_proof_tree = proof_tree.flatten();
        for (node_id, _) in tables_by_node.iter() {
            let prover_node = flattened_proof_tree
                .get(node_id)
                .expect("missing node in proof tree");
            prover_node.add_virtual_witness(&mut piop_tree, prover);
        }
        piop_tree
    }

    pub fn into_parts(
        self,
    ) -> (
        ProverProofTree<F, MvPCS, UvPCS>,
        IndexMap<NodeId, HashMap<String, TrackedTable<F, MvPCS, UvPCS>>>,
    ) {
        let ProverPIOPTree {
            tracked_tables,
            inner_proof_tree,
        } = self;
        (inner_proof_tree, tracked_tables)
    }
}

impl<'a, F, MvPCS, UvPCS> IntoIterator for &'a ProverPIOPTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    type Item = (
        &'a NodeId,
        &'a HashMap<String, TrackedTable<F, MvPCS, UvPCS>>,
    );
    type IntoIter = indexmap::map::Iter<'a, NodeId, HashMap<String, TrackedTable<F, MvPCS, UvPCS>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.tracked_tables.iter()
    }
}

impl<F, MvPCS, UvPCS> IntoIterator for ProverPIOPTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    type Item = (NodeId, HashMap<String, TrackedTable<F, MvPCS, UvPCS>>);
    type IntoIter = indexmap::map::IntoIter<NodeId, HashMap<String, TrackedTable<F, MvPCS, UvPCS>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.tracked_tables.into_iter()
    }
}

struct VirtualNodesDebug<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    inner: &'a IndexMap<NodeId, HashMap<String, TrackedTable<F, MvPCS, UvPCS>>>,
}

impl<'a, F, MvPCS, UvPCS> fmt::Debug for VirtualNodesDebug<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (node_id, tables) in self.inner.iter() {
            map.entry(
                &NodeIdDebug { node_id },
                &VirtualTablesDebug { inner: tables },
            );
        }
        map.finish()
    }
}

struct NodeIdDebug<'a> {
    node_id: &'a NodeId,
}

impl<'a> fmt::Debug for NodeIdDebug<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.node_id.to_string())
    }
}

struct VirtualTablesDebug<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    inner: &'a HashMap<String, TrackedTable<F, MvPCS, UvPCS>>,
}

impl<'a, F, MvPCS, UvPCS> fmt::Debug for VirtualTablesDebug<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (label, table) in self.inner.iter() {
            map.entry(label, table);
        }
        map.finish()
    }
}

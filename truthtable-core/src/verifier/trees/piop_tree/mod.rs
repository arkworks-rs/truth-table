pub mod display;

#[cfg(test)]
mod tests;

use core::fmt;

use crate::{
    proof_nodes::id::NodeId,
    verifier::trees::{proof_tree::VerifierProofTree, tracked_tree::VerifierTrackedTree},
};
use arithmetic::table_oracle::TrackedTableOracle;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    verifier::Verifier,
};
use indexmap::IndexMap;

/// Virtualized tables indexed by proof-plan node identifier.
pub struct VerifierPIOPTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    arena: IndexMap<NodeId, IndexMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>,
    inner_proof_tree: VerifierProofTree<F, MvPCS, UvPCS>,
}

impl<F, MvPCS, UvPCS> fmt::Debug for VerifierPIOPTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifierPIOPTree")
            .field("num_nodes", &self.arena.len())
            .field("nodes", &VirtualNodesDebug { inner: &self.arena })
            .finish()
    }
}

impl<F, MvPCS, UvPCS> VerifierPIOPTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub fn new(
        proof_tree: VerifierProofTree<F, MvPCS, UvPCS>,
        arena: IndexMap<NodeId, IndexMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>,
    ) -> Self {
        Self {
            arena,
            inner_proof_tree: proof_tree,
        }
    }

    pub fn len(&self) -> usize {
        self.arena.len()
    }

    pub fn is_empty(&self) -> bool {
        self.arena.is_empty()
    }

    pub fn arena(
        &self,
    ) -> &IndexMap<NodeId, IndexMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>> {
        &self.arena
    }

    pub fn verify(&mut self, verifier: &mut Verifier<F, MvPCS, UvPCS>) -> SnarkResult<()> {
        self.inner_proof_tree
            .root()
            .verify_piop_recursive(verifier, self)
    }

    pub fn tracked_table_oracles_for(
        &self,
        node_id: &NodeId,
    ) -> Option<&IndexMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>> {
        self.arena.get(node_id)
    }

    pub fn proof_tree(&self) -> &VerifierProofTree<F, MvPCS, UvPCS> {
        &self.inner_proof_tree
    }

    pub fn display_graphviz(&self) -> display::DisplayableVerifierPIOPTree<'_, F, MvPCS, UvPCS> {
        display::DisplayableVerifierPIOPTree::new(self)
    }

    pub fn tracked_table_oracle(
        &self,
        node_id: &NodeId,
        label: &str,
    ) -> Option<&TrackedTableOracle<F, MvPCS, UvPCS>> {
        self.arena
            .get(node_id)
            .and_then(|by_label| by_label.get(label))
    }

    pub fn add_tracked_table_oracle(
        &mut self,
        node_id: NodeId,
        label: String,
        table: TrackedTableOracle<F, MvPCS, UvPCS>,
    ) {
        self.arena.entry(node_id).or_default().insert(label, table);
    }

    /// Build a virtualized plan from an arithmetized plan.
    pub fn from_tracked_tree(
        tracked_tree: VerifierTrackedTree<F, MvPCS, UvPCS>,
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
    ) -> Self {
        let (proof_tree, tables_by_node) = tracked_tree.into_parts();
        let flattened_proof_tree = proof_tree.flatten();

        let mut ordered_tables = IndexMap::new();
        for node_id in flattened_proof_tree.keys() {
            if let Some(tables) = tables_by_node.get(node_id) {
                ordered_tables.insert(node_id.clone(), tables.clone());
            }
        }
        for (node_id, tables) in tables_by_node.into_iter() {
            ordered_tables.entry(node_id).or_insert(tables);
        }

        let mut piop_tree = VerifierPIOPTree::new(proof_tree.clone(), ordered_tables);
        piop_tree
            .inner_proof_tree
            .root()
            .add_virtual_witness_recursive(&mut piop_tree, verifier);
        piop_tree
    }

    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        VerifierProofTree<F, MvPCS, UvPCS>,
        IndexMap<NodeId, IndexMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>,
    ) {
        let VerifierPIOPTree {
            arena,
            inner_proof_tree,
        } = self;
        (inner_proof_tree, arena)
    }
}

impl<'a, F, MvPCS, UvPCS> IntoIterator for &'a VerifierPIOPTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    type Item = (
        &'a NodeId,
        &'a IndexMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>,
    );
    type IntoIter =
        indexmap::map::Iter<'a, NodeId, IndexMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.arena.iter()
    }
}

impl<F, MvPCS, UvPCS> IntoIterator for VerifierPIOPTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    type Item = (
        NodeId,
        IndexMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>,
    );
    type IntoIter =
        indexmap::map::IntoIter<NodeId, IndexMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.arena.into_iter()
    }
}

struct VirtualNodesDebug<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    inner: &'a IndexMap<NodeId, IndexMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>,
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
    inner: &'a IndexMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>,
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

mod display;

use std::{collections::HashMap, fmt};

use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS, verifier::Verifier,
};
use indexmap::IndexMap;

use crate::{id::NodeId, verifier_trees::proof_tree::VerifierProofTree};

/// Virtualized tables indexed by proof-plan node identifier.
pub struct VerifierPIOPTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    tables: IndexMap<NodeId, HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>,
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
            .field("num_nodes", &self.tables.len())
            .field(
                "nodes",
                &VirtualNodesDebug {
                    inner: &self.tables,
                },
            )
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
        tables: IndexMap<NodeId, HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>,
    ) -> Self {
        Self {
            tables,
            inner_proof_tree: proof_tree,
        }
    }

    pub fn len(&self) -> usize {
        self.tables.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tables.is_empty()
    }

    pub fn tables(&self) -> &IndexMap<NodeId, HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>> {
        &self.tables
    }

    pub fn tables_for(
        &self,
        node_id: &NodeId,
    ) -> Option<&HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>> {
        self.tables.get(node_id)
    }

    pub fn proof_tree(&self) -> &VerifierProofTree<F, MvPCS, UvPCS> {
        &self.inner_proof_tree
    }

    pub fn display_graphviz(&self) -> display::DisplayableVerifierPIOPTree<'_, F, MvPCS, UvPCS> {
        display::DisplayableVerifierPIOPTree::new(self)
    }

    pub fn add_table(
        &mut self,
        node_id: NodeId,
        label: String,
        table: TrackedTableOracle<F, MvPCS, UvPCS>,
    ) {
        self.tables.entry(node_id).or_default().insert(label, table);
    }

    pub fn table(&self, node_id: &NodeId, label: &str) -> Option<&TrackedTableOracle<F, MvPCS, UvPCS>> {
        self.tables
            .get(node_id)
            .and_then(|by_label| by_label.get(label))
    }

    /// Build a virtualized plan from an arithmetized plan.
    pub fn from_proof_plan(
        arith_plan: VerifierProofTree<F, MvPCS, UvPCS>,
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
    ) -> Self {
        todo!()
    }

    pub fn into_parts(
        self,
    ) -> (
        VerifierProofTree<F, MvPCS, UvPCS>,
        IndexMap<NodeId, HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>,
    ) {
        let VerifierPIOPTree {
            tables,
            inner_proof_tree,
        } = self;
        (inner_proof_tree, tables)
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
        &'a HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>,
    );
    type IntoIter = indexmap::map::Iter<'a, NodeId, HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.tables.iter()
    }
}

impl<F, MvPCS, UvPCS> IntoIterator for VerifierPIOPTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    type Item = (NodeId, HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>);
    type IntoIter = indexmap::map::IntoIter<NodeId, HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.tables.into_iter()
    }
}

struct VirtualNodesDebug<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    inner: &'a IndexMap<NodeId, HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>,
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
    inner: &'a HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>,
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
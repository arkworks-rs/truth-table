pub mod display;

#[cfg(test)]
mod tests;

use std::{collections::HashMap, fmt};

use arithmetic::table::ArithTable;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};

use crate::trees::{
    arithmetized_tree::ArithmetizedTree,
    proof_tree::{ProofTree, nodes::ProverNodeNodeId},
};

/// Virtualized tables indexed by proof-plan node identifier.
pub struct PIOPTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    tables: HashMap<ProverNodeNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>>,
    inner_proof_tree: ProofTree,
}

impl<F, MvPCS, UvPCS> fmt::Debug for PIOPTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PIOPTree")
            .field("num_nodes", &self.tables.len())
            .field("nodes", &VirtualNodesDebug { inner: &self.tables })
            .finish()
    }
}

impl<F, MvPCS, UvPCS> PIOPTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub fn new(
        proof_tree: ProofTree,
        tables: HashMap<ProverNodeNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>>,
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

    pub fn tables_for(
        &self,
        node_id: &ProverNodeNodeId,
    ) -> Option<&HashMap<String, ArithTable<F, MvPCS, UvPCS>>> {
        self.tables.get(node_id)
    }

    pub fn proof_tree(&self) -> &ProofTree {
        &self.inner_proof_tree
    }

    pub fn display_graphviz(&self) -> display::DisplayablePIOPTree<'_, F, MvPCS, UvPCS> {
        display::DisplayablePIOPTree::new(self)
    }

    pub fn table_for(
        &self,
        node_id: &ProverNodeNodeId,
        label: &str,
    ) -> Option<&ArithTable<F, MvPCS, UvPCS>> {
        self.tables.get(node_id).and_then(|by_label| by_label.get(label))
    }

    /// Build a virtualized plan from an arithmetized plan.
    pub fn from_arithmetized_plan(arith_plan: ArithmetizedTree<F, MvPCS, UvPCS>) -> Self {
        let (proof_tree, mut tables_by_node) = arith_plan.into_parts();
        let flattened_proof_tree = proof_tree.flatten();
        for (node_id, node_table) in tables_by_node.iter_mut() {
            let prover_node = flattened_proof_tree.get(node_id).expect("missing node in proof tree");
            prover_node.piop_plan();
        }

        Self::new(proof_tree, tables_by_node)
    }

    pub fn into_parts(
        self,
    ) -> (
        ProofTree,
        HashMap<ProverNodeNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>>,
    ) {
        let PIOPTree {
            tables,
            inner_proof_tree,
        } = self;
        (inner_proof_tree, tables)
    }
}

impl<'a, F, MvPCS, UvPCS> IntoIterator for &'a PIOPTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type Item = (
        &'a ProverNodeNodeId,
        &'a HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
    );
    type IntoIter = std::collections::hash_map::Iter<
        'a,
        ProverNodeNodeId,
        HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.tables.iter()
    }
}

impl<F, MvPCS, UvPCS> IntoIterator for PIOPTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type Item = (
        ProverNodeNodeId,
        HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
    );
    type IntoIter = std::collections::hash_map::IntoIter<
        ProverNodeNodeId,
        HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.tables.into_iter()
    }
}

struct VirtualNodesDebug<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    inner: &'a HashMap<ProverNodeNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>>,
}

impl<'a, F, MvPCS, UvPCS> fmt::Debug for VirtualNodesDebug<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
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
    node_id: &'a ProverNodeNodeId,
}

impl<'a> fmt::Debug for NodeIdDebug<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.node_id.to_string())
    }
}

struct VirtualTablesDebug<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    inner: &'a HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
}

impl<'a, F, MvPCS, UvPCS> fmt::Debug for VirtualTablesDebug<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (label, table) in self.inner.iter() {
            map.entry(label, table);
        }
        map.finish()
    }
}

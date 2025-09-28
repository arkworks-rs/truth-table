pub mod display;

use std::{collections::HashMap, fmt};

use arithmetic::{errors::EncodeError, table::ArithTable};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    prover::Prover,
};

use crate::trees::{
    hint_tree::HintTree,
    proof_tree::{ProofTree, nodes::ProverNodeNodeId},
};
#[cfg(test)]
pub mod tests;
/// A data structure holding the arithmetized hint tables needed to prove a
/// given proof-tree.
///
/// Although this is called a "tree", it is actually a hash map from tree nodes
/// to their associated hint data, since we don't need the topology of the
/// prover nodes any more. This discrepancy is to keep a consistent naming for
/// the IRs.
pub struct ArithmetizedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    tables: HashMap<ProverNodeNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>>,
    inner_proof_tree: ProofTree<F, MvPCS, UvPCS>,
}

impl<F, MvPCS, UvPCS> fmt::Debug for ArithmetizedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArithmetizedTree")
            .field("num_nodes", &self.tables.len())
            .field(
                "nodes",
                &ArithNodesDebug {
                    inner: &self.tables,
                },
            )
            .finish()
    }
}

impl<F, MvPCS, UvPCS> ArithmetizedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub fn new(
        proof_tree: ProofTree<F, MvPCS, UvPCS>,
        tables: HashMap<ProverNodeNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>>,
    ) -> Self {
        Self {
            tables,
            inner_proof_tree: proof_tree,
        }
    }

    pub fn table_by_node_map(
        self,
    ) -> HashMap<ProverNodeNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>> {
        let (_, tables) = self.into_parts();
        tables
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

    pub fn table_for(
        &self,
        node_id: &ProverNodeNodeId,
        label: &str,
    ) -> Option<&ArithTable<F, MvPCS, UvPCS>> {
        self.tables
            .get(node_id)
            .and_then(|by_label| by_label.get(label))
    }

    pub fn proof_tree(&self) -> &ProofTree<F, MvPCS, UvPCS> {
        &self.inner_proof_tree
    }

    pub fn display_graphviz(&self) -> display::DisplayableArithmetizedTree<'_, F, MvPCS, UvPCS> {
        display::DisplayableArithmetizedTree::new(self)
    }

    pub fn into_parts(
        self,
    ) -> (
        ProofTree<F, MvPCS, UvPCS>,
        HashMap<ProverNodeNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>>,
    ) {
        let ArithmetizedTree {
            tables,
            inner_proof_tree,
        } = self;
        (inner_proof_tree, tables)
    }

    /// Build arithmetized tables for every hint node by consuming a hint
    /// tree.
    #[tracing::instrument(name = "arithmetized_tree::from_hint_tree", skip(hint_tree, prover))]
    pub fn from_hint_tree(
        hint_tree: HintTree<F, MvPCS, UvPCS>,
        prover: &mut Prover<F, MvPCS, UvPCS>,
    ) -> Result<Self, EncodeError> {
        let (proof_tree, hint_map) = hint_tree.into_parts();
        let mut tables_by_node: HashMap<
            ProverNodeNodeId,
            HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
        > = HashMap::with_capacity(hint_map.len());

        for (node_id, batches_by_label) in hint_map {
            let mut arith_tables = HashMap::with_capacity(batches_by_label.len());
            for (label, batches) in batches_by_label {
                let table = ArithTable::<F, MvPCS, UvPCS>::from_record_batches(batches, prover)?;
                arith_tables.insert(label, table);
            }
            tables_by_node.insert(node_id, arith_tables);
        }

        Ok(Self::new(proof_tree, tables_by_node))
    }
}

impl<'a, F, MvPCS, UvPCS> IntoIterator for &'a ArithmetizedTree<F, MvPCS, UvPCS>
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

impl<F, MvPCS, UvPCS> IntoIterator for ArithmetizedTree<F, MvPCS, UvPCS>
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

struct ArithNodesDebug<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    inner: &'a HashMap<ProverNodeNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>>,
}

impl<'a, F, MvPCS, UvPCS> fmt::Debug for ArithNodesDebug<'a, F, MvPCS, UvPCS>
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
                &ArithTablesDebug { inner: tables },
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
struct ArithTablesDebug<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    inner: &'a HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
}

impl<'a, F, MvPCS, UvPCS> fmt::Debug for ArithTablesDebug<'a, F, MvPCS, UvPCS>
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

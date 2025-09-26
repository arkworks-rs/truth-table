pub mod display;

use std::{collections::HashMap, fmt};

use arithmetic::{errors::EncodeError, table::ArithTable};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    prover::Prover,
};

use crate::{
    nodes::{ProverNodeNodeId},
    trees::hint_tree::HintTree,
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
pub struct ArithmetizedTree<F, MvPCS, UvPCS>(
    HashMap<ProverNodeNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>>,
)
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>;

impl<F, MvPCS, UvPCS> fmt::Debug for ArithmetizedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArithmetizedTree")
            .field("num_nodes", &self.0.len())
            .field("nodes", &ArithNodesDebug { inner: &self.0 })
            .finish()
    }
}

impl<F, MvPCS, UvPCS> ArithmetizedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub fn new(
        tables: HashMap<ProverNodeNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>>,
    ) -> Self {
        Self(tables)
    }

    pub fn table_by_node_map(
        self,
    ) -> HashMap<ProverNodeNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn tables_for(
        &self,
        node_id: &ProverNodeNodeId,
    ) -> Option<&HashMap<String, ArithTable<F, MvPCS, UvPCS>>> {
        self.0.get(node_id)
    }

    pub fn table_for(
        &self,
        node_id: &ProverNodeNodeId,
        label: &str,
    ) -> Option<&ArithTable<F, MvPCS, UvPCS>> {
        self.0.get(node_id).and_then(|by_label| by_label.get(label))
    }

    /// Build arithmetized tables for every hint node by consuming a hint
    /// tree.
    #[tracing::instrument(name = "arithmetized_tree::from_hint_tree", skip(hint_tree, prover))]
    pub fn from_hint_tree(
        hint_tree: HintTree,
        prover: &mut Prover<F, MvPCS, UvPCS>,
    ) -> Result<Self, EncodeError> {
        let mut tables_by_node: HashMap<
            ProverNodeNodeId,
            HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
        > = HashMap::with_capacity(hint_tree.len());

        for (node_id, batches_by_label) in hint_tree.into_iter() {
            let mut arith_tables = HashMap::with_capacity(batches_by_label.len());
            for (label, batches) in batches_by_label {
                let table = ArithTable::<F, MvPCS, UvPCS>::from_record_batches(batches, prover)?;
                arith_tables.insert(label, table);
            }
            tables_by_node.insert(node_id, arith_tables);
        }

        Ok(Self::new(tables_by_node))
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
        self.0.iter()
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
        self.0.into_iter()
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

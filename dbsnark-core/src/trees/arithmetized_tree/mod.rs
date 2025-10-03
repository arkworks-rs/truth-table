use std::{collections::HashMap, fmt};

use arithmetic::table::SerializableArithTable;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};

use crate::trees::{
    proof_tree::{ProofTree, nodes::ProverNodeNodeId},
    tracked_tree::TrackedTree,
};

pub struct ArithmetizedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    tables: HashMap<ProverNodeNodeId, HashMap<String, SerializableArithTable<F>>>,
    inner_proof_tree: ProofTree<F, MvPCS, UvPCS>,
}

impl<F, MvPCS, UvPCS> fmt::Debug for ArithmetizedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArithmetizedTree")
            .field("num_nodes", &self.tables.len())
            .field(
                "nodes",
                &ArithNodesDebug::<F> {
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
        tables: HashMap<ProverNodeNodeId, HashMap<String, SerializableArithTable<F>>>,
    ) -> Self {
        Self {
            tables,
            inner_proof_tree: proof_tree,
        }
    }

    pub fn from_tracked_tree(tracked: TrackedTree<F, MvPCS, UvPCS>) -> Self {
        let (proof_tree, tables) = tracked.into_parts();
        let serializable_tables = tables
            .into_iter()
            .map(|(node_id, by_label)| {
                let converted = by_label
                    .into_iter()
                    .map(|(label, table)| (label, SerializableArithTable::from(table)))
                    .collect();
                (node_id, converted)
            })
            .collect();
        Self::new(proof_tree, serializable_tables)
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
    ) -> Option<&HashMap<String, SerializableArithTable<F>>> {
        self.tables.get(node_id)
    }

    pub fn table_for(
        &self,
        node_id: &ProverNodeNodeId,
        label: &str,
    ) -> Option<&SerializableArithTable<F>> {
        self.tables
            .get(node_id)
            .and_then(|tables| tables.get(label))
    }

    pub fn proof_tree(&self) -> &ProofTree<F, MvPCS, UvPCS> {
        &self.inner_proof_tree
    }

    pub fn into_parts(
        self,
    ) -> (
        ProofTree<F, MvPCS, UvPCS>,
        HashMap<ProverNodeNodeId, HashMap<String, SerializableArithTable<F>>>,
    ) {
        let ArithmetizedTree {
            tables,
            inner_proof_tree,
        } = self;
        (inner_proof_tree, tables)
    }
}

impl<F, MvPCS, UvPCS> IntoIterator for ArithmetizedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    type Item = (ProverNodeNodeId, HashMap<String, SerializableArithTable<F>>);
    type IntoIter = std::collections::hash_map::IntoIter<
        ProverNodeNodeId,
        HashMap<String, SerializableArithTable<F>>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.tables.into_iter()
    }
}

struct ArithNodesDebug<'a, F>
where
    F: PrimeField,
{
    inner: &'a HashMap<ProverNodeNodeId, HashMap<String, SerializableArithTable<F>>>,
}

impl<'a, F> fmt::Debug for ArithNodesDebug<'a, F>
where
    F: PrimeField,
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

struct ArithTablesDebug<'a, F>
where
    F: PrimeField,
{
    inner: &'a HashMap<String, SerializableArithTable<F>>,
}

impl<'a, F> fmt::Debug for ArithTablesDebug<'a, F>
where
    F: PrimeField,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (label, table) in self.inner.iter() {
            map.entry(label, table);
        }
        map.finish()
    }
}

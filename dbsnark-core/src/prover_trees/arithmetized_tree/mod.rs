use crate::id::NodeId;
pub mod display;
#[cfg(test)]
pub mod tests;

use std::{collections::HashMap, fmt, sync::Arc};

use ark_std::cfg_into_iter;
use indexmap::IndexMap;

use arithmetic::{encoding::encode_arrow_array_to_field, errors::EncodeError, table::ArithTable};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::arrow::{
    datatypes::{FieldRef, Schema},
    record_batch::RecordBatch,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::prover_trees::{hint_tree::ProverHintTree, proof_tree::ProverProofTree};

pub struct ProverArithmetizedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    tables: IndexMap<NodeId, HashMap<String, ArithTable<F>>>,
    inner_proof_tree: ProverProofTree<F, MvPCS, UvPCS>,
}

impl<F, MvPCS, UvPCS> fmt::Debug for ProverArithmetizedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProverArithmetizedTree")
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

impl<F, MvPCS, UvPCS> ProverArithmetizedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub fn new(
        proof_tree: ProverProofTree<F, MvPCS, UvPCS>,
        tables: IndexMap<NodeId, HashMap<String, ArithTable<F>>>,
    ) -> Self {
        Self {
            tables,
            inner_proof_tree: proof_tree,
        }
    }

    #[tracing::instrument(name = "arithmetized_tree::from_hint_tree", skip(hint_tree))]
    pub fn from_hint_tree(hint_tree: ProverHintTree<F, MvPCS, UvPCS>) -> Result<Self, EncodeError> {
        let (proof_tree, hint_map) = hint_tree.into_parts();
        let mut tables_by_node = IndexMap::with_capacity(hint_map.len());

        for (node_id, batches_by_label) in hint_map {
            let mut tables = HashMap::with_capacity(batches_by_label.len());
            for (label, batches) in batches_by_label {
                let serial_table = Self::arith_table_from_batches(batches)?;
                tables.insert(label, serial_table);
            }
            tables_by_node.insert(node_id, tables);
        }

        Ok(Self::new(proof_tree, tables_by_node))
    }

    #[tracing::instrument(level = "debug", skip(record_batches))]
    pub(crate) fn arith_table_from_batches(
        record_batches: Vec<RecordBatch>,
    ) -> Result<ArithTable<F>, EncodeError> {
        if record_batches.is_empty() {
            return Ok(ArithTable::new(None, Vec::new(), 0));
        }

        let schema_ref = record_batches[0].schema();
        let num_cols = schema_ref.fields().len();
        let total_rows: usize = record_batches.iter().map(|b| b.num_rows()).sum();
        assert!(total_rows.is_power_of_two());
        let log_vars = total_rows.trailing_zeros() as usize;

        let columns: Result<Vec<Vec<F>>, EncodeError> = cfg_into_iter!(0..num_cols)
            .map(|col_idx| {
                let mut values = Vec::with_capacity(total_rows);
                for batch in &record_batches {
                    let encoded = encode_arrow_array_to_field::<F>(batch.column(col_idx))?;
                    assert!(encoded.len() == 1, "Expected a single column encoding, We cannot handle multi-column encodings yet"); 
                    let mut column_values = encoded.into_iter().next().expect("encoded column");
                    values.append(&mut column_values);
                }
                Ok(values)
            })
            .collect();
        let columns = columns?;

        let data_polys: Vec<(FieldRef, Arc<MLE<F>>)> = cfg_into_iter!(columns)
            .enumerate()
            .map(|(idx, values)| {
                let mle = Arc::new(MLE::from_evaluations_slice(log_vars, &values));
                let field_ref = Arc::new(schema_ref.field(idx).clone());
                (field_ref, mle)
            })
            .collect();

        let schema = Some(schema_ref.as_ref().clone());

        Ok(ArithTable::new(schema, data_polys, total_rows))
    }

    pub fn len(&self) -> usize {
        self.tables.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tables.is_empty()
    }

    pub fn tables_for(&self, node_id: &NodeId) -> Option<&HashMap<String, ArithTable<F>>> {
        self.tables.get(node_id)
    }

    pub fn table_for(&self, node_id: &NodeId, label: &str) -> Option<&ArithTable<F>> {
        self.tables
            .get(node_id)
            .and_then(|tables| tables.get(label))
    }

    pub fn proof_tree(&self) -> &ProverProofTree<F, MvPCS, UvPCS> {
        &self.inner_proof_tree
    }

    pub fn display_graphviz(
        &self,
    ) -> display::DisplayableProverArithmetizedTree<'_, F, MvPCS, UvPCS> {
        display::DisplayableProverArithmetizedTree::new(self)
    }

    pub fn into_parts(
        self,
    ) -> (
        ProverProofTree<F, MvPCS, UvPCS>,
        IndexMap<NodeId, HashMap<String, ArithTable<F>>>,
    ) {
        let ProverArithmetizedTree {
            tables,
            inner_proof_tree,
        } = self;
        (inner_proof_tree, tables)
    }
}

impl<F, MvPCS, UvPCS> IntoIterator for ProverArithmetizedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    type Item = (NodeId, HashMap<String, ArithTable<F>>);
    type IntoIter = indexmap::map::IntoIter<NodeId, HashMap<String, ArithTable<F>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.tables.into_iter()
    }
}

struct ArithNodesDebug<'a, F>
where
    F: PrimeField,
{
    inner: &'a IndexMap<NodeId, HashMap<String, ArithTable<F>>>,
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
                &TrackedTablesDebug { inner: tables },
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

struct TrackedTablesDebug<'a, F>
where
    F: PrimeField,
{
    inner: &'a HashMap<String, ArithTable<F>>,
}

impl<'a, F> fmt::Debug for TrackedTablesDebug<'a, F>
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

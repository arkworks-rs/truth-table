pub mod display;
#[cfg(test)]
pub mod tests;

use std::{fmt, sync::Arc};

use crate::proof_nodes::id::NodeId;
use arithmetic::{encoding::encode_arrow_array_to_field, errors::EncodeError, table::ArithTable};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use ark_std::cfg_into_iter;
use datafusion::arrow::{
    compute::concat_batches,
    datatypes::{Field, FieldRef, Schema},
    record_batch::RecordBatch,
};
use indexmap::IndexMap;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use tracing::instrument;

use crate::prover::trees::{hint_tree::ProverHintTree, proof_tree::ProverProofTree};

pub struct ProverArithmetizedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    arena: IndexMap<NodeId, IndexMap<String, ArithTable<F>>>,
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
            .field("num_nodes", &self.arena.len())
            .field("nodes", &ArithNodesDebug::<F> { inner: &self.arena })
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
        arena: IndexMap<NodeId, IndexMap<String, ArithTable<F>>>,
    ) -> Self {
        Self {
            arena,
            inner_proof_tree: proof_tree,
        }
    }

    fn perform_arithmetic_post_process(arith_tree: &mut Self) {
        let nodes: Vec<_> = arith_tree
            .inner_proof_tree
            .arena()
            .values()
            .cloned()
            .collect();

        for node in nodes {
            node.arithmetic_post_process(arith_tree);
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub fn from_hint_tree(hint_tree: ProverHintTree<F, MvPCS, UvPCS>) -> Result<Self, EncodeError> {
        let (proof_tree, hint_map) = hint_tree.into_parts();
        let mut tables_by_node = IndexMap::with_capacity(hint_map.len());

        for (node_id, batches_by_label) in hint_map {
            let mut tables = IndexMap::with_capacity(batches_by_label.len());
            for (label, batches) in batches_by_label {
                let serial_table = Self::arith_table_from_batches(batches)?;
                tables.insert(label, serial_table);
            }
            tables_by_node.insert(node_id, tables);
        }
        let mut output_arith_tree = Self::new(proof_tree, tables_by_node);
        Self::perform_arithmetic_post_process(&mut output_arith_tree);
        Ok(output_arith_tree)
    }

    #[tracing::instrument(level = "debug", skip(record_batches))]
    pub(crate) fn arith_table_from_batches(
        record_batches: Vec<RecordBatch>,
    ) -> Result<ArithTable<F>, EncodeError> {
        if record_batches.is_empty() {
            return Ok(ArithTable::new(None, IndexMap::new(), 0));
        }

        let schema_ref = record_batches[0].schema();
        let combined_batch = concat_batches(&schema_ref, &record_batches).map_err(|err| {
            EncodeError::TypeNotSupported(format!("Failed to concatenate record batches: {err}"))
        })?;

        let total_rows = combined_batch.num_rows();
        assert!(
            total_rows.is_power_of_two(),
            "Arithmetized tables must have power-of-two number of rows, got {}",
            total_rows
        );
        let log_vars = total_rows.trailing_zeros() as usize;

        let num_total_cols = schema_ref.fields().len();

        let encoded_columns: Result<Vec<Vec<(FieldRef, Vec<F>)>>, EncodeError> =
            cfg_into_iter!(0..num_total_cols)
                .map(|col_idx| {
                    let base_field = schema_ref.fields()[col_idx].clone();
                    let encoded = encode_arrow_array_to_field::<F>(combined_batch.column(col_idx))?;
                    let mut segmented = Vec::with_capacity(encoded.len());
                    for (segment_idx, values) in encoded.into_iter().enumerate() {
                        debug_assert!(
                            values.len() == total_rows,
                            "Encoded column length mismatch: expected {total_rows}, got {}",
                            values.len()
                        );
                        let field_ref = if segment_idx == 0 {
                            base_field.clone()
                        } else {
                            Arc::new(Field::new(
                                &format!("{}__enc{}", base_field.name(), segment_idx),
                                base_field.data_type().clone(),
                                base_field.is_nullable(),
                            ))
                        };
                        segmented.push((field_ref, values));
                    }
                    Ok(segmented)
                })
                .collect();
        let encoded_columns = encoded_columns?;

        let mut flattened_fields: Vec<FieldRef> = Vec::new();
        let mut flattened_values: Vec<(FieldRef, Vec<F>)> = Vec::new();
        for column_group in encoded_columns {
            for (field_ref, values) in column_group {
                flattened_fields.push(field_ref.clone());
                flattened_values.push((field_ref, values));
            }
        }

        let tracked_polys_entries: Vec<(FieldRef, Arc<MLE<F>>)> = flattened_values
            .into_iter()
            .map(|(field_ref, values)| {
                let mle = Arc::new(MLE::from_evaluations_slice(log_vars, &values));
                (field_ref, mle)
            })
            .collect();
        let tracked_polys: IndexMap<FieldRef, Arc<MLE<F>>> =
            tracked_polys_entries.into_iter().collect();
        let schema_fields: Vec<Field> = flattened_fields
            .iter()
            .map(|field_ref| field_ref.as_ref().clone())
            .collect();
        let schema = Some(Schema::new(schema_fields));

        Ok(ArithTable::new(schema, tracked_polys, log_vars))
    }

    pub fn len(&self) -> usize {
        self.arena.len()
    }

    pub fn is_empty(&self) -> bool {
        self.arena.is_empty()
    }

    pub fn arithmetized_tables_for(
        &self,
        node_id: &NodeId,
    ) -> Option<&IndexMap<String, ArithTable<F>>> {
        self.arena.get(node_id)
    }

    pub fn arithmetized_tables(&self) -> &IndexMap<NodeId, IndexMap<String, ArithTable<F>>> {
        &self.arena
    }

    pub fn arithmetized_tables_for_mut(
        &mut self,
        node_id: &NodeId,
    ) -> Option<&mut IndexMap<String, ArithTable<F>>> {
        self.arena.get_mut(node_id)
    }

    pub fn arithmetized_table_for(&self, node_id: &NodeId, label: &str) -> Option<&ArithTable<F>> {
        self.arena.get(node_id).and_then(|tables| tables.get(label))
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
        IndexMap<NodeId, IndexMap<String, ArithTable<F>>>,
    ) {
        let ProverArithmetizedTree {
            arena,
            inner_proof_tree,
        } = self;
        (inner_proof_tree, arena)
    }
}

impl<F, MvPCS, UvPCS> IntoIterator for ProverArithmetizedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    type Item = (NodeId, IndexMap<String, ArithTable<F>>);
    type IntoIter = indexmap::map::IntoIter<NodeId, IndexMap<String, ArithTable<F>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.arena.into_iter()
    }
}

struct ArithNodesDebug<'a, F>
where
    F: PrimeField,
{
    inner: &'a IndexMap<NodeId, IndexMap<String, ArithTable<F>>>,
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
    inner: &'a IndexMap<String, ArithTable<F>>,
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

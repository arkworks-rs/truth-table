pub mod display;

use std::{collections::HashMap, fmt, hash::Hash, sync::Arc};

use crate::trees::{
    hint_tree::HintTree,
    proof_tree::{ProofTree, nodes::ProverNodeNodeId},
};
use arithmetic::{
    ctx::ProverCtx, encoding::encode_arrow_array_to_field, errors::EncodeError, table::ArithTable,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    prover::{Prover, structs::polynomial::TrackedPoly},
};
use datafusion::{
    arrow::{
        array::RecordBatch,
        datatypes::{FieldRef, Schema},
    },
    logical_expr::LogicalPlan,
};
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use tracing_subscriber::field::debug;
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
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    tables: HashMap<ProverNodeNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>>,
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
        let (mut proof_tree, hint_map) = hint_tree.into_parts();
        let mut prover_ctx = proof_tree.ctx_mut();
        let mut tables_by_node: HashMap<
            ProverNodeNodeId,
            HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
        > = HashMap::with_capacity(hint_map.len());

        for (node_id, batches_by_label) in hint_map {
            let mut arith_tables = HashMap::with_capacity(batches_by_label.len());
            for (label, batches) in batches_by_label {
                let table = Self::arith_table_from_record_batches_and_ctx(
                    &node_id,
                    batches,
                    &mut prover_ctx,
                    prover,
                )?;
                arith_tables.insert(label, table);
            }
            tables_by_node.insert(node_id, arith_tables);
        }

        Ok(Self::new(proof_tree, tables_by_node))
    }

    /// Computes an Arithmetic table from a vector of record batches
    /// If the columns are already commited and are in the prover context, they
    /// will not be commited again
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn arith_table_from_record_batches_and_ctx(
        node_id: &ProverNodeNodeId,
        record_batches: Vec<RecordBatch>,
        prover_ctx: &mut ProverCtx<F, MvPCS, UvPCS>,
        prover: &mut Prover<F, MvPCS, UvPCS>,
    ) -> Result<ArithTable<F, MvPCS, UvPCS>, EncodeError> {
        // If there is no record batch, just output empty arithmetic tables
        if record_batches.is_empty() {
            return Ok(ArithTable::new(None, Vec::new(), 0));
        }
        // Get the schema ref of the record batches
        let schema_ref = record_batches[0].schema();
        // Get the number of columns in the record batches
        let num_cols = schema_ref.fields().len();
        // Get the number of rows in the record batches
        let total_rows: usize = record_batches.iter().map(|b| b.num_rows()).sum();
        // Assert that the number of rows are a power of two
        assert!(total_rows.is_power_of_two());
        // Get the log of the number of rows
        let max_log_vars = total_rows.trailing_zeros() as usize;
        // Get the values for each column in the record batches
        let columns: Result<Vec<Vec<F>>, EncodeError> = (0..num_cols)
            .into_par_iter()
            .map(|col_idx| {
                let mut values = Vec::with_capacity(total_rows);
                for batch in &record_batches {
                    let encoded = encode_arrow_array_to_field::<F>(batch.column(col_idx))?;
                    // TODO: The current version only supports single column encoding
                    let mut column_values = encoded.into_iter().next().expect("encoded column");
                    values.append(&mut column_values);
                }
                Ok(values)
            })
            .collect();
        let mut columns = columns?;

        // Turn the columns into MLE polynomials
        let column_polys: HashMap<FieldRef, Arc<MLE<F>>> = columns
            .into_par_iter()
            .enumerate()
            .map(|(idx, values)| {
                let mle = MLE::from_evaluations_slice(max_log_vars, &values);
                let field_ref = Arc::new(schema_ref.field(idx).clone());
                (field_ref, Arc::new(mle))
            })
            .collect();

        let prover_param = prover.mv_pcs_prover_param();

        let mut poly_to_commitments_map: HashMap<&MLE<F>, MvPCS::Commitment> =
            HashMap::with_capacity(column_polys.len());
        for (field_ref, poly) in &column_polys {
            let commitment = if let Some(commitment) =
                prover_ctx.already_committed_poly(poly).cloned()
            {
                commitment
            } else {
                let saved_commitment = if let ProverNodeNodeId::LP(LogicalPlan::TableScan(_)) =
                    node_id
                {
                    prover_ctx
                        .table_oracle(schema_ref.as_ref())
                        .map(|saved_table| {
                            tracing::debug!("Table column {:?} was already committed", field_ref);
                            saved_table
                                .data_comitments()
                                .get(field_ref)
                                .cloned()
                                .unwrap()
                        })
                } else {
                    None
                };

                if let Some(commitment) = saved_commitment {
                    commitment
                } else {
                    MvPCS::commit(prover_param.clone(), poly)
                        .expect("failed to commit witness polynomial")
                }
            };
            prover_ctx.add_committed_poly(poly.clone(), commitment.clone());
            poly_to_commitments_map.insert(poly, commitment);
        }

        let mut data_polys: Vec<(FieldRef, TrackedPoly<F, MvPCS, UvPCS>)> =
            Vec::with_capacity(num_cols);

        for idx in 0..num_cols {
            let field_ref = Arc::new(schema_ref.field(idx).clone());
            let poly_arc = column_polys
                .get(&field_ref)
                .expect("polynomial for field not found")
                .clone();
            let commitment = poly_to_commitments_map
                .get(poly_arc.as_ref())
                .expect("commitment for field not found")
                .clone();

            let tracked = prover
                .track_mat_mv_poly_with_commitment(poly_arc.as_ref(), commitment)
                .expect("failed to commit witness polynomial");
            data_polys.push((field_ref.clone(), tracked));
        }

        let schema = Some(Schema::new(
            schema_ref
                .fields()
                .iter()
                .cloned()
                .collect::<datafusion::arrow::datatypes::Fields>(),
        ));

        Ok(ArithTable::new(schema, data_polys, total_rows))
    }
}

impl<'a, F, MvPCS, UvPCS> IntoIterator for &'a ArithmetizedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
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
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
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
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    inner: &'a HashMap<ProverNodeNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>>,
}

impl<'a, F, MvPCS, UvPCS> fmt::Debug for ArithNodesDebug<'a, F, MvPCS, UvPCS>
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
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    inner: &'a HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
}

impl<'a, F, MvPCS, UvPCS> fmt::Debug for ArithTablesDebug<'a, F, MvPCS, UvPCS>
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

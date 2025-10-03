pub mod display;

use std::{collections::HashMap, fmt, sync::Arc};

use crate::trees::{
    arithmetized_tree::ArithmetizedTree,
    hint_tree::HintTree,
    proof_tree::{ProofTree, nodes::ProverNodeNodeId},
};
use arithmetic::{
    ctx::ProverCtx,
    errors::EncodeError,
    table::{TrackedTable, ArithTable},
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    prover::{Prover, structs::polynomial::TrackedPoly},
};
use datafusion::{
    arrow::{array::RecordBatch, datatypes::FieldRef},
    logical_expr::LogicalPlan,
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
pub struct TrackedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    tables: HashMap<ProverNodeNodeId, HashMap<String, TrackedTable<F, MvPCS, UvPCS>>>,
    inner_proof_tree: ProofTree<F, MvPCS, UvPCS>,
}

impl<F, MvPCS, UvPCS> fmt::Debug for TrackedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrackedTree")
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

impl<F, MvPCS, UvPCS> TrackedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub fn new(
        proof_tree: ProofTree<F, MvPCS, UvPCS>,
        tables: HashMap<ProverNodeNodeId, HashMap<String, TrackedTable<F, MvPCS, UvPCS>>>,
    ) -> Self {
        Self {
            tables,
            inner_proof_tree: proof_tree,
        }
    }

    pub fn table_by_node_map(
        self,
    ) -> HashMap<ProverNodeNodeId, HashMap<String, TrackedTable<F, MvPCS, UvPCS>>> {
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
    ) -> Option<&HashMap<String, TrackedTable<F, MvPCS, UvPCS>>> {
        self.tables.get(node_id)
    }

    pub fn table_for(
        &self,
        node_id: &ProverNodeNodeId,
        label: &str,
    ) -> Option<&TrackedTable<F, MvPCS, UvPCS>> {
        self.tables
            .get(node_id)
            .and_then(|by_label| by_label.get(label))
    }

    pub fn proof_tree(&self) -> &ProofTree<F, MvPCS, UvPCS> {
        &self.inner_proof_tree
    }

    pub fn display_graphviz(&self) -> display::DisplayableTrackedTree<'_, F, MvPCS, UvPCS> {
        display::DisplayableTrackedTree::new(self)
    }

    pub fn into_parts(
        self,
    ) -> (
        ProofTree<F, MvPCS, UvPCS>,
        HashMap<ProverNodeNodeId, HashMap<String, TrackedTable<F, MvPCS, UvPCS>>>,
    ) {
        let TrackedTree {
            tables,
            inner_proof_tree,
        } = self;
        (inner_proof_tree, tables)
    }


    #[tracing::instrument(
        name = "tracked_tree::from_arithmetized_tree",
        skip(arith_tree, prover)
    )]
    pub fn from_arithmetized_tree(
        arith_tree: ArithmetizedTree<F, MvPCS, UvPCS>,
        prover: &mut Prover<F, MvPCS, UvPCS>,
    ) -> Result<Self, EncodeError> {
        let (mut proof_tree, serial_tables) = arith_tree.into_parts();
        let mut prover_ctx = proof_tree.ctx_mut();
        let mut tables_by_node: HashMap<
            ProverNodeNodeId,
            HashMap<String, TrackedTable<F, MvPCS, UvPCS>>,
        > = HashMap::with_capacity(serial_tables.len());

        for (node_id, tables) in serial_tables {
            let mut tracked_Tables = HashMap::with_capacity(tables.len());
            for (label, serial_table) in tables {
                let table = Self::tracked_table_from_serializable(
                    &node_id,
                    serial_table,
                    &mut prover_ctx,
                    prover,
                );
                tracked_Tables.insert(label, table);
            }
            tables_by_node.insert(node_id, tracked_Tables);
        }

        Ok(Self::new(proof_tree, tables_by_node))
    }

    /// Computes an arithmetic table from a vector of record batches by
    /// first turning them into serializable tables and then tracking the
    /// resulting polynomials.
    #[tracing::instrument(level = "debug", skip(record_batches, prover_ctx, prover))]
    pub fn tracked_table_from_record_batches_and_ctx(
        node_id: &ProverNodeNodeId,
        record_batches: Vec<RecordBatch>,
        prover_ctx: &mut ProverCtx<F, MvPCS, UvPCS>,
        prover: &mut Prover<F, MvPCS, UvPCS>,
    ) -> Result<TrackedTable<F, MvPCS, UvPCS>, EncodeError> {
        let serial_table =
            ArithmetizedTree::<F, MvPCS, UvPCS>::arith_table_from_batches(record_batches)?;
        Ok(Self::tracked_table_from_serializable(
            node_id,
            serial_table,
            prover_ctx,
            prover,
        ))
    }

    fn tracked_table_from_serializable(
        node_id: &ProverNodeNodeId,
        serial_table: ArithTable<F>,
        prover_ctx: &mut ProverCtx<F, MvPCS, UvPCS>,
        prover: &mut Prover<F, MvPCS, UvPCS>,
    ) -> TrackedTable<F, MvPCS, UvPCS> {
        let schema = serial_table.schema();
        let size = serial_table.size();
        let num_cols = serial_table.num_cols();

        if num_cols == 0 {
            return TrackedTable::new(schema, Vec::new(), size);
        }

        let prover_param = prover.mv_pcs_prover_param();
        let mut data_polys: Vec<(FieldRef, TrackedPoly<F, MvPCS, UvPCS>)> =
            Vec::with_capacity(num_cols);

        for (field_ref, mle) in serial_table.data_polys() {
            let poly_arc = Arc::new(mle.clone());
            let commitment = if let Some(commitment) = prover_ctx
                .already_committed_poly(poly_arc.as_ref())
                .cloned()
            {
                commitment
            } else {
                let saved_commitment =
                    if let (ProverNodeNodeId::LP(LogicalPlan::TableScan(_)), Some(schema_ref)) =
                        (node_id, schema.as_ref())
                    {
                        prover_ctx.table_oracle(schema_ref).and_then(|saved_table| {
                            saved_table.data_comitments().get(field_ref).cloned()
                        })
                    } else {
                        None
                    };

                if let Some(commitment) = saved_commitment {
                    commitment
                } else {
                    MvPCS::commit(prover_param.clone(), &poly_arc)
                        .expect("failed to commit witness polynomial")
                }
            };

            prover_ctx.add_committed_poly(poly_arc.clone(), commitment.clone());

            let tracked = prover
                .track_mat_mv_poly_with_commitment(poly_arc.as_ref(), commitment)
                .expect("failed to commit witness polynomial");
            data_polys.push((field_ref.clone(), tracked));
        }

        TrackedTable::new(schema, data_polys, size)
    }
}

impl<'a, F, MvPCS, UvPCS> IntoIterator for &'a TrackedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    type Item = (
        &'a ProverNodeNodeId,
        &'a HashMap<String, TrackedTable<F, MvPCS, UvPCS>>,
    );
    type IntoIter = std::collections::hash_map::Iter<
        'a,
        ProverNodeNodeId,
        HashMap<String, TrackedTable<F, MvPCS, UvPCS>>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.tables.iter()
    }
}

impl<F, MvPCS, UvPCS> IntoIterator for TrackedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    type Item = (
        ProverNodeNodeId,
        HashMap<String, TrackedTable<F, MvPCS, UvPCS>>,
    );
    type IntoIter = std::collections::hash_map::IntoIter<
        ProverNodeNodeId,
        HashMap<String, TrackedTable<F, MvPCS, UvPCS>>,
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
    inner: &'a HashMap<ProverNodeNodeId, HashMap<String, TrackedTable<F, MvPCS, UvPCS>>>,
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
                &TrackedTablesDebug { inner: tables },
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
struct TrackedTablesDebug<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    inner: &'a HashMap<String, TrackedTable<F, MvPCS, UvPCS>>,
}

impl<'a, F, MvPCS, UvPCS> fmt::Debug for TrackedTablesDebug<'a, F, MvPCS, UvPCS>
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

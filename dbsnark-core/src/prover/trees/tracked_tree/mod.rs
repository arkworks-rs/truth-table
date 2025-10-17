use crate::prover::trees::{
    arithmetized_tree::ProverArithmetizedTree, proof_tree::ProverProofTree,
};
pub mod display;
use crate::proof_nodes::id::NodeId;
use std::{fmt, sync::Arc};

use arithmetic::{errors::EncodeError, table::TrackedTable};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    prover::{Prover, structs::polynomial::TrackedPoly},
};
use ark_std::cfg_into_iter;
use datafusion::{arrow::datatypes::FieldRef, logical_expr::LogicalPlan};
use indexmap::IndexMap;
#[cfg(feature = "parallel")]
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use tracing::{info, instrument};
#[cfg(test)]
pub mod tests;
/// A data structure holding the arithmetized hint tables needed to prove a
/// given proof-tree.
///
/// Although this is called a "tree", it is actually a hash map from tree nodes
/// to their associated hint data, since we don't need the topology of the
/// prover nodes any more. This discrepancy is to keep a consistent naming for
/// the IRs.
pub struct ProverTrackedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    arena: IndexMap<NodeId, IndexMap<String, TrackedTable<F, MvPCS, UvPCS>>>,
    inner_proof_tree: ProverProofTree<F, MvPCS, UvPCS>,
}

impl<F, MvPCS, UvPCS> fmt::Debug for ProverTrackedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProverTrackedTree")
            .field("num_nodes", &self.arena.len())
            .field(
                "nodes",
                &ArithNodesDebug {
                    inner: &self.arena,
                },
            )
            .finish()
    }
}

impl<F, MvPCS, UvPCS> ProverTrackedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub fn new(
        proof_tree: ProverProofTree<F, MvPCS, UvPCS>,
        arena: IndexMap<NodeId, IndexMap<String, TrackedTable<F, MvPCS, UvPCS>>>,
    ) -> Self {
        Self {
            arena,
            inner_proof_tree: proof_tree,
        }
    }

    pub fn table_by_node_map(
        self,
    ) -> IndexMap<NodeId, IndexMap<String, TrackedTable<F, MvPCS, UvPCS>>> {
        let (_, tables) = self.into_parts();
        tables
    }

    pub fn len(&self) -> usize {
        self.arena.len()
    }

    pub fn is_empty(&self) -> bool {
        self.arena.is_empty()
    }

    pub fn tracked_tables_for(
        &self,
        node_id: &NodeId,
    ) -> Option<&IndexMap<String, TrackedTable<F, MvPCS, UvPCS>>> {
        self.arena.get(node_id)
    }

    pub fn tracked_table_for(
        &self,
        node_id: &NodeId,
        label: &str,
    ) -> Option<&TrackedTable<F, MvPCS, UvPCS>> {
        self.arena
            .get(node_id)
            .and_then(|by_label| by_label.get(label))
    }

    pub fn arena(
        &self,
    ) -> &IndexMap<NodeId, IndexMap<String, TrackedTable<F, MvPCS, UvPCS>>> {
        &self.arena
    }

    pub fn proof_tree(&self) -> &ProverProofTree<F, MvPCS, UvPCS> {
        &self.inner_proof_tree
    }

    pub fn display_graphviz(&self) -> display::DisplayableProverTrackedTree<'_, F, MvPCS, UvPCS> {
        display::DisplayableProverTrackedTree::new(self)
    }

    pub fn into_parts(
        self,
    ) -> (
        ProverProofTree<F, MvPCS, UvPCS>,
        IndexMap<NodeId, IndexMap<String, TrackedTable<F, MvPCS, UvPCS>>>,
    ) {
        let ProverTrackedTree {
            arena,
            inner_proof_tree,
        } = self;
        (inner_proof_tree, arena)
    }

    #[instrument(level = "debug", skip_all)]
    pub fn from_arithmetized_tree(
        arith_tree: ProverArithmetizedTree<F, MvPCS, UvPCS>,
        prover: &mut Prover<F, MvPCS, UvPCS>,
    ) -> Result<Self, EncodeError> {
        let (mut proof_tree, node_arith_tables) = arith_tree.into_parts();
        let prover_ctx = proof_tree.ctx_mut();
        let mut commitment_map: IndexMap<Arc<MLE<F>>, Option<MvPCS::Commitment>> = IndexMap::new();
        // First initialize the commitment mapping for all polynomials in the
        // arithmetized tree.
        for (_, arith_tables) in &node_arith_tables {
            for arith_table in arith_tables.values() {
                for (_, mle) in arith_table.polynomials() {
                    commitment_map.insert(mle.clone(), None);
                }
            }
        }

        // Now, if a node was a TableScan and we have a saved oracle for it, use the
        // saved comitments to avoid recomputing them.
        for (node_id, arith_tables) in &node_arith_tables {
            let is_table_scan = matches!(node_id, NodeId::LP(LogicalPlan::TableScan(_)));
            for arith_table in arith_tables.values() {
                if let Some(schema) = arith_table.schema() {
                    if is_table_scan {
                        for (field_ref, mle) in arith_table.polynomials() {
                            let saved_commitment =
                                prover_ctx
                                    .table_oracle(&schema)
                                    .and_then(|saved_table_oracle| {
                                        saved_table_oracle.comitments().get(field_ref).cloned()
                                    });
                            commitment_map.insert(mle.clone(), saved_commitment);
                        }
                    }
                }
            }
        }

        // Now build a list of all polynomials that are still missing comitments
        let missing_comitments: Vec<Arc<MLE<F>>> = commitment_map
            .iter()
            .filter_map(|(mle_arc, com_opt)| {
                if com_opt.is_none() {
                    Some(mle_arc.clone())
                } else {
                    None
                }
            })
            .collect();

        let pcs_param = prover.mv_pcs_prover_param().clone();

        let new_comitments: Vec<_> = cfg_into_iter!(missing_comitments)
            .map(|mle_arc| {
                let commitment = MvPCS::commit(pcs_param.clone(), &mle_arc)
                    .expect("failed to commit witness polynomial");
                (mle_arc, commitment)
            })
            .collect();

        info!("Prover committed to {} polynomials", new_comitments.len());

        for (mle_arc, commitment) in new_comitments {
            let entry = commitment_map
                .get_mut(&mle_arc)
                .expect("missing commitment for polynomial");
            *entry = Some(commitment);
        }
        let mut tables_by_node: IndexMap<NodeId, IndexMap<String, TrackedTable<F, MvPCS, UvPCS>>> =
            IndexMap::with_capacity(node_arith_tables.len());
        let mut tracked_count = 0;
        for (node_id, tables) in node_arith_tables {
            let mut tracked_tables = IndexMap::with_capacity(tables.len());
            for (label, arith_table) in tables {
                let num_total_cols = arith_table.num_total_cols();
                let table = if num_total_cols == 0 {
                    TrackedTable::new(
                        arith_table.schema(),
                        IndexMap::new(),
                        arith_table.log_size(),
                    )
                } else {
                    let mut tracked_polys: IndexMap<FieldRef, TrackedPoly<F, MvPCS, UvPCS>> =
                        IndexMap::with_capacity(num_total_cols);

                    for (field_ref, mle) in arith_table.polynomials() {
                        let commitment = commitment_map
                            .get(mle)
                            .expect("missing commitment for polynomial")
                            .clone()
                            .expect("missing commitment for polynomial");
                        let tracked = prover
                            .track_mat_mv_poly_with_commitment(mle.as_ref(), commitment)
                            .expect("failed to commit witness polynomial");
                        tracked_polys.insert(field_ref.clone(), tracked);
                        tracked_count += 1;
                    }

                    TrackedTable::new(arith_table.schema(), tracked_polys, arith_table.log_size())
                };

                tracked_tables.insert(label, table);
            }
            tables_by_node.insert(node_id, tracked_tables);
        }
        info!("Prover tracked {} polynomials", tracked_count);
        Ok(Self::new(proof_tree, tables_by_node))
    }
}

impl<'a, F, MvPCS, UvPCS> IntoIterator for &'a ProverTrackedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    type Item = (
        &'a NodeId,
        &'a IndexMap<String, TrackedTable<F, MvPCS, UvPCS>>,
    );
    type IntoIter =
        indexmap::map::Iter<'a, NodeId, IndexMap<String, TrackedTable<F, MvPCS, UvPCS>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.arena.iter()
    }
}

impl<F, MvPCS, UvPCS> IntoIterator for ProverTrackedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    type Item = (NodeId, IndexMap<String, TrackedTable<F, MvPCS, UvPCS>>);
    type IntoIter =
        indexmap::map::IntoIter<NodeId, IndexMap<String, TrackedTable<F, MvPCS, UvPCS>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.arena.into_iter()
    }
}

struct ArithNodesDebug<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    inner: &'a IndexMap<NodeId, IndexMap<String, TrackedTable<F, MvPCS, UvPCS>>>,
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
    node_id: &'a NodeId,
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
    inner: &'a IndexMap<String, TrackedTable<F, MvPCS, UvPCS>>,
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

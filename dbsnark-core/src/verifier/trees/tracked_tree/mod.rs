use crate::{
    id::NodeId,
    verifier::{nodes::VerifierNode, trees::proof_tree::VerifierProofTree},
};
use arithmetic::table_oracle::TrackedTableOracle;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    verifier::Verifier,
};
use indexmap::IndexMap;
use std::{collections::HashMap, fmt, sync::Arc};

mod display;
#[cfg(test)]
mod tests;

pub struct VerifierTrackedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    tables: IndexMap<NodeId, HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>,
    inner_proof_tree: VerifierProofTree<F, MvPCS, UvPCS>,
}

impl<F, MvPCS, UvPCS> fmt::Debug for VerifierTrackedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifierTrackedTree")
            .field("num_nodes", &self.tables.len())
            .finish()
    }
}

impl<F, MvPCS, UvPCS> VerifierTrackedTree<F, MvPCS, UvPCS>
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

    pub fn table_by_node_map(
        self,
    ) -> IndexMap<NodeId, HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>> {
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
        node_id: &NodeId,
    ) -> Option<&HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>> {
        self.tables.get(node_id)
    }

    pub fn table_for(
        &self,
        node_id: &NodeId,
        label: &str,
    ) -> Option<&TrackedTableOracle<F, MvPCS, UvPCS>> {
        self.tables
            .get(node_id)
            .and_then(|by_label| by_label.get(label))
    }

    pub fn proof_tree(&self) -> &VerifierProofTree<F, MvPCS, UvPCS> {
        &self.inner_proof_tree
    }

    pub fn display_graphviz(&self) -> display::DisplayableVerifierTrackedTree<'_, F, MvPCS, UvPCS> {
        display::DisplayableVerifierTrackedTree::new(self)
    }

    pub fn into_parts(
        self,
    ) -> (
        VerifierProofTree<F, MvPCS, UvPCS>,
        IndexMap<NodeId, HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>,
    ) {
        let VerifierTrackedTree {
            tables,
            inner_proof_tree,
        } = self;
        (inner_proof_tree, tables)
    }

    pub fn from_proof_tree(
        proof_tree: VerifierProofTree<F, MvPCS, UvPCS>,
        _verifier: &mut Verifier<F, MvPCS, UvPCS>,
    ) -> VerifierTrackedTree<F, MvPCS, UvPCS> {
        todo!()
        //         let root = proof_tree.root();

        //         fn collect<F, MvPCS, UvPCS>(
        //             node: &Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
        //             out: &mut Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
        //         ) where
        //             F: PrimeField,
        //             MvPCS: PCS<F, Poly = MLE<F>> + 'static,
        //             UvPCS: PCS<F, Poly = LDE<F>> + 'static,
        //         {
        //             for child in node.children() {
        //                 collect(child, out);
        //             }
        //             out.push(Arc::clone(node));
        //         }

        //         let mut nodes = Vec::new();
        //         collect(&root, &mut nodes);

        //         let mut by_id: HashMap<usize, HashMap<String, DFSchemaRef>> =
        // HashMap::new();         for node in &nodes {
        //             let plans = node.hint_generation_plans();
        //             if plans.is_empty() {
        //                 continue;
        //             }
        //             let entry = by_id.entry(node_ptr_id(node)).or_default();
        //             for (label, plan) in plans {
        //                 entry.insert(label, plan.schema().clone());
        //             }
        //         }

        //         for node in &nodes {
        //             by_id.entry(node_ptr_id(node)).or_default();
        //         }

        //         let node_count = nodes.len();
        //         let (mut table_scan_nodes, mut other_nodes): (Vec<_>, Vec<_>)
        // =             nodes.into_iter().partition(|node| {
        //                 node.as_any()
        //                     .downcast_ref::<TableScanNode>()
        //                     .is_some()
        //             });
        //         table_scan_nodes.extend(other_nodes);

        //         let mut results_by_node_id: IndexMap<NodeId, HashMap<String,
        // DFSchemaRef>> =
        // IndexMap::with_capacity(node_count);         for node in
        // table_scan_nodes {             let node_id = node.node_id();
        //             let ptr_id = node_ptr_id(&node);
        //             let entry = by_id.remove(&ptr_id).unwrap_or_default();
        //             results_by_node_id.insert(node_id, entry);
        //         }

        //   let prover_ctx = proof_tree.ctx_mut();
        //         let mut commitment_map: HashMap<Arc<MLE<F>>,
        // Option<MvPCS::Commitment>> = HashMap::new();         // First
        // initialize the commitment mapping for all polynomials in the
        //         // arithmetized tree.
        //         for (_, arith_tables) in &node_arith_tables {
        //             for arith_table in arith_tables.values() {
        //                 for (_, mle) in arith_table.data_polys() {
        //                     commitment_map.insert(mle.clone(), None);
        //                 }
        //             }
        //         }

        //         // Now, if a node was a TableScan and we have a saved oracle
        // for it, use the         // saved commitments to avoid
        // recomputing them.         for (node_id, arith_tables) in
        // &node_arith_tables {             let is_table_scan =
        // matches!(node_id, NodeId::LP(LogicalPlan::TableScan(_)));
        //             for arith_table in arith_tables.values() {
        //                 if let Some(schema) = arith_table.schema() {
        //                     if is_table_scan {
        //                         for (field_ref, mle) in
        // arith_table.data_polys() {                             let
        // saved_commitment =                                 prover_ctx
        //                                     .table_oracle(&schema)
        //                                     .and_then(|saved_table_oracle| {
        //
        // saved_table_oracle.data_comitments().get(field_ref).cloned()
        //                                     });
        //                             commitment_map.insert(mle.clone(),
        // saved_commitment);                         }
        //                     }
        //                 }
        //             }
        //         }

        //         // Now build a list of all polynomials that are still missing
        // commitments         let missing_commitments: Vec<Arc<MLE<F>>>
        // = commitment_map             .iter()
        //             .filter_map(|(mle_arc, com_opt)| {
        //                 if com_opt.is_none() {
        //                     Some(mle_arc.clone())
        //                 } else {
        //                     None
        //                 }
        //             })
        //             .collect();

        //         let pcs_param = prover.mv_pcs_prover_param().clone();

        //         let new_commitments: Vec<_> =
        // cfg_into_iter!(missing_commitments)
        // .map(|mle_arc| {                 let commitment =
        // MvPCS::commit(pcs_param.clone(), &mle_arc)
        // .expect("failed to commit witness polynomial");
        // (mle_arc, commitment)             })
        //             .collect();

        //         for (mle_arc, commitment) in new_commitments {
        //             let entry = commitment_map
        //                 .get_mut(&mle_arc)
        //                 .expect("missing commitment for polynomial");
        //             *entry = Some(commitment);
        //         }
        //         let mut tables_by_node: IndexMap<NodeId, HashMap<String,
        // TrackedTable<F, MvPCS, UvPCS>>> =
        // IndexMap::with_capacity(node_arith_tables.len());         for
        // (node_id, tables) in node_arith_tables {             let mut
        // tracked_tables = HashMap::with_capacity(tables.len());
        //             for (label, arith_table) in tables {
        //                 let num_total_cols = arith_table.num_total_cols();
        //                 let table = if num_total_cols == 0 {
        //                     TrackedTable::new(arith_table.schema(),
        // Vec::new(), arith_table.size())                 } else {
        //                     let mut data_polys: Vec<(FieldRef, TrackedPoly<F,
        // MvPCS, UvPCS>)> =
        // Vec::with_capacity(num_total_cols);

        //                     for (field_ref, mle) in arith_table.data_polys()
        // {                         let commitment = commitment_map
        //                             .get(mle)
        //                             .expect("missing commitment for
        // polynomial")                             .clone()
        //                             .expect("missing commitment for
        // polynomial");                         let tracked = prover
        //
        // .track_mat_mv_poly_with_commitment(mle.as_ref(), commitment)
        //                             .expect("failed to commit witness
        // polynomial");
        // data_polys.push((field_ref.clone(), tracked));
        // }

        //                     TrackedTable::new(arith_table.schema(),
        // data_polys, arith_table.size())                 };

        //                 tracked_tables.insert(label, table);
        //             }
        //             tables_by_node.insert(node_id, tracked_tables);
        //         }

        //         Ok(Self::new(proof_tree, tables_by_node))
    }
}

fn node_ptr_id<F, MvPCS, UvPCS>(node: &Arc<dyn VerifierNode<F, MvPCS, UvPCS>>) -> usize
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    let data_ptr = &**node as *const dyn VerifierNode<F, MvPCS, UvPCS> as *const ();
    data_ptr as usize
}

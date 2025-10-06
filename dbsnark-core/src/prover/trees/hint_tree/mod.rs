use crate::id::NodeId;
pub mod display;
#[cfg(test)]
pub mod tests;

use std::{collections::HashMap, fmt, sync::Arc};

use indexmap::IndexMap;

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{
    arrow::{
        array::{Array, BooleanArray},
        record_batch::RecordBatch,
    },
    error::Result as DFResult,
    prelude::SessionContext,
};

use futures::{
    FutureExt,
    future::{BoxFuture, try_join_all},
};
use tracing::{debug, trace};

use crate::prover::{
    nodes::{ProverNode, lps::TableScanNode},
    trees::proof_tree::ProverProofTree,
};

/// A data structure holding the hint tables needed to prove a given proof-tree.
///
/// Although this is called a "tree", it is actually a hash map from tree nodes
/// to their associated hint data, since we don't need the topology of the
/// prover nodes any more. This discrepancy is to keep a consistent naming for
/// the IRs.
pub struct ProverHintTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    hint_map: IndexMap<NodeId, HashMap<String, Vec<RecordBatch>>>,
    inner_proof_tree: ProverProofTree<F, MvPCS, UvPCS>,
}

impl<F, MvPCS, UvPCS> fmt::Debug for ProverHintTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProverHintTree")
            .field("num_nodes", &self.hint_map.len())
            .field(
                "nodes",
                &HintNodesDebug {
                    inner: &self.hint_map,
                },
            )
            .finish()
    }
}

impl<F, MvPCS, UvPCS> ProverHintTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub fn new(
        proof_tree: ProverProofTree<F, MvPCS, UvPCS>,
        hint_map: IndexMap<NodeId, HashMap<String, Vec<RecordBatch>>>,
    ) -> Self {
        Self {
            hint_map,
            inner_proof_tree: proof_tree,
        }
    }

    pub fn len(&self) -> usize {
        self.hint_map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hint_map.is_empty()
    }

    /// Return the batches collected for a specific hint label at the
    /// requested proof-tree node, if present.
    pub fn batches_for(&self, node_id: &NodeId, label: &str) -> Option<&Vec<RecordBatch>> {
        self.hint_map
            .get(node_id)
            .and_then(|by_label| by_label.get(label))
    }

    /// Heuristic to pick a "primary" result set for a proof-tree node. Prefers
    /// `output_tree`, falls back to `relative_output`, then any entry.
    pub fn primary_batches(&self, node_id: &NodeId) -> Option<&Vec<RecordBatch>> {
        self.batches_for(node_id, "output_tree")
            .or_else(|| self.batches_for(node_id, "relative_output"))
            .or_else(|| self.hint_map.get(node_id).and_then(|m| m.values().next()))
    }

    pub fn results_for(&self, node_id: &NodeId) -> Option<&HashMap<String, Vec<RecordBatch>>> {
        self.hint_map.get(node_id)
    }

    pub fn proof_tree(&self) -> &ProverProofTree<F, MvPCS, UvPCS> {
        &self.inner_proof_tree
    }

    pub fn display_graphviz(&self) -> display::DisplayableProverHintTree<'_, F, MvPCS, UvPCS> {
        display::DisplayableProverHintTree::new(self)
    }

    pub fn hint_map(&self) -> &IndexMap<NodeId, HashMap<String, Vec<RecordBatch>>> {
        &self.hint_map
    }

    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        ProverProofTree<F, MvPCS, UvPCS>,
        IndexMap<NodeId, HashMap<String, Vec<RecordBatch>>>,
    ) {
        let ProverHintTree {
            hint_map,
            inner_proof_tree,
        } = self;
        (inner_proof_tree, hint_map)
    }

    /// Execute the proof tree and assemble a hint tree mirroring the
    /// proof-tree shape. All hint-generation logical plans are executed in
    /// parallel.
    #[tracing::instrument(name = "hint_tree::from_proof_tree", skip_all)]
    pub async fn from_proof_tree(
        ctx: &SessionContext,
        proof_tree: ProverProofTree<F, MvPCS, UvPCS>,
    ) -> DFResult<Self> {
        let root = proof_tree.root();
        // Walk the proof tree once to gather every node in post-order while
        // also recording how far each node sits from the root. This depth map
        // later drives a deterministic which is shared between the prover and the
        // verifier. This ordering is necessary for the prover and the verifier to be in
        // sync.
        fn collect<F, MvPCS, UvPCS>(
            node: &Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
            depth: usize,
            depths: &mut HashMap<usize, usize>,
            out: &mut Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
        ) where
            F: PrimeField,
            MvPCS: PCS<F, Poly = MLE<F>> + 'static,
            UvPCS: PCS<F, Poly = LDE<F>> + 'static,
        {
            for c in node.children() {
                collect(c, depth + 1, depths, out);
            }
            depths.insert(node_ptr_id(node), depth);
            out.push(Arc::clone(node));
        }
        let mut nodes = Vec::new();
        let mut depths = HashMap::new();
        collect(&root, 0, &mut depths, &mut nodes);

        #[allow(clippy::type_complexity)]
        let mut futures: Vec<
            BoxFuture<'static, DFResult<(usize, String, Vec<RecordBatch>)>>,
        > = Vec::new();

        for node in &nodes {
            let trees = node.hint_generation_plans();
            for (label, tree) in trees {
                let ctx = ctx.clone();
                let node = Arc::clone(node);
                futures.push(
                    async move {
                        // Optimize and materialize the hint plan tied to this
                        // node/label pair.
                        debug!(node = tree_label(&node), tree_label = %label, "executing hint tree");
                        let tree = ctx.state().optimize(&tree).unwrap();
                        let df = ctx.execute_logical_plan(tree).await?;
                        let batches = df.collect().await?;

                        if label == "output_tree"
                            && node.as_any().downcast_ref::<TableScanNode>().is_some()
                        {
                            let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
                            assert!(
                                rows != 0 && (rows & (rows - 1)) == 0,
                                "TableScan rows not power-of-two: {}",
                                rows
                            );
                        }

                        let (rows, cols, activated) = rows_cols_activated(&batches);
                        trace!(
                            node = tree_label(&node),
                            tree_label = %label,
                            rows,
                            cols,
                            activated_true = activated.unwrap_or(rows),
                            "hint batches collected"
                        );

                        Ok((node_ptr_id(&node), label, batches))
                    }
                    .boxed(),
                );
            }
        }

        // Wait for all hint plans to finish and bucket the batches by node id.
        let results = try_join_all(futures).await?;

        let mut by_id: HashMap<usize, HashMap<String, Vec<RecordBatch>>> = HashMap::new();
        for (id, label, batches) in results {
            by_id.entry(id).or_default().insert(label, batches);
        }

        // Guarantee every proof-tree node has a map entry, even if it produced no
        // hints, so consumers always find a placeholder structure.
        for node in &nodes {
            by_id.entry(node_ptr_id(node)).or_default();
        }

        let node_count = nodes.len();
        // Split nodes into table scans and everything else so we can honor the
        // "table scans first" constraint.
        let mut table_scan_nodes: Vec<_> = nodes
            .iter()
            .filter(|&node| node.as_any().downcast_ref::<TableScanNode>().is_some())
            .cloned()
            .collect();
        let mut other_nodes: Vec<_> = nodes
            .iter()
            .filter(|&node| node.as_any().downcast_ref::<TableScanNode>().is_none())
            .cloned()
            .collect();

        let cmp_nodes = |a: &Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
                         b: &Arc<dyn ProverNode<F, MvPCS, UvPCS>>| {
            let depth_a = depths.get(&node_ptr_id(a)).copied().unwrap_or(0);
            let depth_b = depths.get(&node_ptr_id(b)).copied().unwrap_or(0);
            depth_b
                .cmp(&depth_a)
                .then_with(|| a.node_id().to_string().cmp(&b.node_id().to_string()))
        };

        table_scan_nodes.sort_by(cmp_nodes);
        other_nodes.sort_by(cmp_nodes);

        // Stitch table scans (already sorted deepest-to-shallow) before the rest.
        let ordered_nodes = table_scan_nodes.into_iter().chain(other_nodes.into_iter());

        let mut results_by_node_id: IndexMap<NodeId, HashMap<String, Vec<RecordBatch>>> =
            IndexMap::with_capacity(node_count);
        // Finally, emit entries following the deterministic order we just
        // computed.
        for node in ordered_nodes {
            let node_id = node.node_id();
            let ptr_id = node_ptr_id(&node);
            let entry = by_id.remove(&ptr_id).unwrap_or_default();
            results_by_node_id.insert(node_id, entry);
        }

        Ok(Self::new(proof_tree, results_by_node_id))
    }
}

impl<'a, F, MvPCS, UvPCS> IntoIterator for &'a ProverHintTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    type Item = (&'a NodeId, &'a HashMap<String, Vec<RecordBatch>>);
    type IntoIter = indexmap::map::Iter<'a, NodeId, HashMap<String, Vec<RecordBatch>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.hint_map.iter()
    }
}

impl<F, MvPCS, UvPCS> IntoIterator for ProverHintTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    type Item = (NodeId, HashMap<String, Vec<RecordBatch>>);
    type IntoIter = indexmap::map::IntoIter<NodeId, HashMap<String, Vec<RecordBatch>>>;

    fn into_iter(self) -> Self::IntoIter {
        let ProverHintTree { hint_map, .. } = self;
        hint_map.into_iter()
    }
}

struct HintNodesDebug<'a> {
    inner: &'a IndexMap<NodeId, HashMap<String, Vec<RecordBatch>>>,
}

impl<'a> fmt::Debug for HintNodesDebug<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (node_id, batches_by_label) in self.inner.iter() {
            map.entry(
                &NodeIdDebug { node_id },
                &HintLabelsDebug {
                    inner: batches_by_label,
                },
            );
        }
        map.finish()
    }
}

struct HintLabelsDebug<'a> {
    inner: &'a HashMap<String, Vec<RecordBatch>>,
}

impl<'a> fmt::Debug for HintLabelsDebug<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (label, batches) in self.inner.iter() {
            map.entry(label, &HintBatchSummary { batches });
        }
        map.finish()
    }
}

struct HintBatchSummary<'a> {
    batches: &'a [RecordBatch],
}

impl<'a> fmt::Debug for HintBatchSummary<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (rows, cols, activated_true) = rows_cols_activated(self.batches);
        f.debug_struct("Batches")
            .field("num_batches", &self.batches.len())
            .field("rows", &rows)
            .field("cols", &cols)
            .field("activated_true", &activated_true)
            .finish()
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

pub(crate) fn tree_label<F, MvPCS, UvPCS>(
    node: &Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
) -> &'static str
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    match node.node_id() {
        NodeId::LP(_) => "LogicalPlan",
        NodeId::Expr(_) => "Expr",
    }
}

/// Stable-ish identifier for a node based on its vtable pointer, used to join
/// asynchronous hint results back to the tree shape.
fn node_ptr_id<F, MvPCS, UvPCS>(p: &Arc<dyn ProverNode<F, MvPCS, UvPCS>>) -> usize {
    let data_ptr = &**p as *const dyn ProverNode<F, MvPCS, UvPCS> as *const ();
    data_ptr as usize
}

// Compute total rows, number of columns, and count of rows with activator=true
// (if an activator column exists). Returns (rows, cols, Some(activated_true))
// or (rows, cols, None) when no activator column is present.
fn rows_cols_activated(batches: &[RecordBatch]) -> (usize, usize, Option<usize>) {
    let rows = batches.iter().map(|b| b.num_rows()).sum::<usize>();
    let cols = batches
        .first()
        .map(|b| b.schema().fields().len())
        .unwrap_or(0);
    // find activator index
    let activator_idx = batches
        .iter()
        .find_map(|b| b.schema().index_of("activator").ok());
    if let Some(_idx) = activator_idx {
        let mut count_true = 0usize;
        for b in batches {
            if let Ok(i) = b.schema().index_of("activator") {
                let mask = b
                    .column(i)
                    .as_any()
                    .downcast_ref::<BooleanArray>()
                    .expect("'activator' must be Boolean");
                for j in 0..mask.len() {
                    if mask.is_valid(j) && mask.value(j) {
                        count_true += 1;
                    }
                }
            }
        }
        (rows, cols, Some(count_true))
    } else {
        (rows, cols, None)
    }
}

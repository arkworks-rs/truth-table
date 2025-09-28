pub mod display;
#[cfg(test)]
pub mod tests;

use std::{collections::HashMap, fmt, sync::Arc};

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

use crate::trees::proof_tree::{
    ProofTree,
    nodes::{ProverNode, ProverNodeNodeId, lps::TableScanNode},
};

/// A data structure holding the hint tables needed to prove a given proof-tree.
///
/// Although this is called a "tree", it is actually a hash map from tree nodes
/// to their associated hint data, since we don't need the topology of the
/// prover nodes any more. This discrepancy is to keep a consistent naming for
/// the IRs.
pub struct HintTree {
    hint_map: HashMap<ProverNodeNodeId, HashMap<String, Vec<RecordBatch>>>,
    inner_proof_tree: ProofTree,
}

impl fmt::Debug for HintTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HintTree")
            .field("num_nodes", &self.hint_map.len())
            .field("nodes", &HintNodesDebug { inner: &self.hint_map })
            .finish()
    }
}

impl HintTree {
    pub fn new(
        proof_tree: ProofTree,
        hint_map: HashMap<ProverNodeNodeId, HashMap<String, Vec<RecordBatch>>>,
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
    pub fn batches_for(
        &self,
        node_id: &ProverNodeNodeId,
        label: &str,
    ) -> Option<&Vec<RecordBatch>> {
        self.hint_map.get(node_id).and_then(|by_label| by_label.get(label))
    }

    /// Heuristic to pick a "primary" result set for a proof-tree node. Prefers
    /// `output_tree`, falls back to `relative_output`, then any entry.
    pub fn primary_batches(&self, node_id: &ProverNodeNodeId) -> Option<&Vec<RecordBatch>> {
        self.batches_for(node_id, "output_tree")
            .or_else(|| self.batches_for(node_id, "relative_output"))
            .or_else(|| self.hint_map.get(node_id).and_then(|m| m.values().next()))
    }

    pub fn results_for(
        &self,
        node_id: &ProverNodeNodeId,
    ) -> Option<&HashMap<String, Vec<RecordBatch>>> {
        self.hint_map.get(node_id)
    }

    pub fn proof_tree(&self) -> &ProofTree {
        &self.inner_proof_tree
    }

    pub fn display_graphviz(&self) -> display::DisplayableHintTree<'_> {
        display::DisplayableHintTree::new(self)
    }

    pub fn into_parts(
        self,
    ) -> (
        ProofTree,
        HashMap<ProverNodeNodeId, HashMap<String, Vec<RecordBatch>>>,
    ) {
        let HintTree {
            hint_map,
            inner_proof_tree,
        } = self;
        (inner_proof_tree, hint_map)
    }

    /// Execute the proof tree and assemble a hint tree mirroring the
    /// proof-tree shape. All hint-generation logical plans are executed in
    /// parallel.
    #[tracing::instrument(name = "hint_tree::from_proof_tree", skip_all)]
    pub async fn from_proof_tree(ctx: &SessionContext, proof_tree: ProofTree) -> DFResult<Self> {
        let root = proof_tree.root();
        // Collect all nodes (post-order) from the proof tree so we can spawn
        // concurrent executions for each node's hint trees.
        fn collect(node: &Arc<dyn ProverNode>, out: &mut Vec<Arc<dyn ProverNode>>) {
            for c in node.children() {
                collect(c, out);
            }
            out.push(Arc::clone(node));
        }
        let mut nodes = Vec::new();
        collect(&root, &mut nodes);

        // Spawn futures for every hint-generation tree across the tree.
        let mut futures: Vec<BoxFuture<'static, DFResult<(usize, String, Vec<RecordBatch>)>>> =
            Vec::new();

        for node in &nodes {
            let trees = node.hint_generation_plans();
            for (label, tree) in trees {
                let ctx = ctx.clone();
                let node = Arc::clone(node);
                futures.push(
                    async move {
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

        let results = try_join_all(futures).await?;

        let mut by_id: HashMap<usize, HashMap<String, Vec<RecordBatch>>> = HashMap::new();
        for (id, label, batches) in results {
            by_id.entry(id).or_default().insert(label, batches);
        }

        // Ensure every proof-tree node has an entry, even if no hint trees were
        // declared, so downstream consumers can rely on presence.
        for node in &nodes {
            by_id.entry(node_ptr_id(node)).or_default();
        }

        let mut results_by_node_id: HashMap<ProverNodeNodeId, HashMap<String, Vec<RecordBatch>>> =
            HashMap::with_capacity(nodes.len());
        for node in nodes {
            let node_id = node.node_id();
            let ptr_id = node_ptr_id(&node);
            let entry = by_id.remove(&ptr_id).unwrap_or_default();
            results_by_node_id.insert(node_id, entry);
        }

        Ok(Self::new(proof_tree, results_by_node_id))
    }
}

impl<'a> IntoIterator for &'a HintTree {
    type Item = (&'a ProverNodeNodeId, &'a HashMap<String, Vec<RecordBatch>>);
    type IntoIter =
        std::collections::hash_map::Iter<'a, ProverNodeNodeId, HashMap<String, Vec<RecordBatch>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.hint_map.iter()
    }
}

impl IntoIterator for HintTree {
    type Item = (ProverNodeNodeId, HashMap<String, Vec<RecordBatch>>);
    type IntoIter =
        std::collections::hash_map::IntoIter<ProverNodeNodeId, HashMap<String, Vec<RecordBatch>>>;

    fn into_iter(self) -> Self::IntoIter {
        let HintTree { hint_map, .. } = self;
        hint_map.into_iter()
    }
}

struct HintNodesDebug<'a> {
    inner: &'a HashMap<ProverNodeNodeId, HashMap<String, Vec<RecordBatch>>>,
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
    node_id: &'a ProverNodeNodeId,
}

impl<'a> fmt::Debug for NodeIdDebug<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.node_id.to_string())
    }
}

pub(crate) fn tree_label(node: &Arc<dyn ProverNode>) -> &'static str {
    match node.node_id() {
        ProverNodeNodeId::LP(_) => "LogicalPlan",
        ProverNodeNodeId::Expr(_) => "Expr",
    }
}

/// Stable-ish identifier for a node based on its vtable pointer, used to join
/// asynchronous hint results back to the tree shape.
fn node_ptr_id(p: &Arc<dyn ProverNode>) -> usize {
    let data_ptr = &**p as *const dyn ProverNode as *const ();
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
    if let Some(idx) = activator_idx {
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

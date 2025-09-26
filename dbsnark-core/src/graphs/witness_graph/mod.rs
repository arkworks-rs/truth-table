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

use crate::nodes::{ProofPlan, ProofPlanNodeId, describe_node_id, lps::TableScanNode};

/// Witness results indexed by proof-plan node identifier.
pub struct WitnessGraph(HashMap<ProofPlanNodeId, HashMap<String, Vec<RecordBatch>>>);

impl fmt::Debug for WitnessGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WitnessGraph")
            .field("num_nodes", &self.0.len())
            .field("nodes", &WitnessNodesDebug { inner: &self.0 })
            .finish()
    }
}

impl WitnessGraph {
    pub fn new(results: HashMap<ProofPlanNodeId, HashMap<String, Vec<RecordBatch>>>) -> Self {
        Self(results)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Return the batches collected for a specific witness label at the
    /// requested proof-plan node, if present.
    pub fn batches_for(&self, node_id: &ProofPlanNodeId, label: &str) -> Option<&Vec<RecordBatch>> {
        self.0.get(node_id).and_then(|by_label| by_label.get(label))
    }

    /// Heuristic to pick a "primary" result set for a proof-plan node. Prefers
    /// `output_plan`, falls back to `relative_output`, then any entry.
    pub fn primary_batches(&self, node_id: &ProofPlanNodeId) -> Option<&Vec<RecordBatch>> {
        self.batches_for(node_id, "output_plan")
            .or_else(|| self.batches_for(node_id, "relative_output"))
            .or_else(|| self.0.get(node_id).and_then(|m| m.values().next()))
    }

    pub fn results_for(
        &self,
        node_id: &ProofPlanNodeId,
    ) -> Option<&HashMap<String, Vec<RecordBatch>>> {
        self.0.get(node_id)
    }

    /// Execute the proof tree and assemble a witness plan mirroring the
    /// proof-plan shape. All witness-generation logical plans are executed in
    /// parallel.
    #[tracing::instrument(name = "witness_plan::from_proof_plan", skip(ctx, root))]
    pub async fn from_proof_plan(ctx: &SessionContext, root: Arc<dyn ProofPlan>) -> DFResult<Self> {
        // Collect all nodes (post-order) from the proof plan so we can spawn
        // concurrent executions for each node's witness plans.
        fn collect(node: &Arc<dyn ProofPlan>, out: &mut Vec<Arc<dyn ProofPlan>>) {
            for c in node.children() {
                collect(c, out);
            }
            out.push(Arc::clone(node));
        }
        let mut nodes = Vec::new();
        collect(&root, &mut nodes);

        // Spawn futures for every witness-generation plan across the tree.
        let mut futures: Vec<BoxFuture<'static, DFResult<(usize, String, Vec<RecordBatch>)>>> =
            Vec::new();

        for node in &nodes {
            let plans = node.witness_generation_plans();
            for (label, plan) in plans {
                let ctx = ctx.clone();
                let node = Arc::clone(node);
                futures.push(
                    async move {
                        debug!(node = plan_label(&node), plan_label = %label, "executing witness plan");
                        let plan = ctx.state().optimize(&plan).unwrap();
                        let df = ctx.execute_logical_plan(plan).await?;
                        let batches = df.collect().await?;

                        if label == "output_plan"
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
                            node = plan_label(&node),
                            plan_label = %label,
                            rows,
                            cols,
                            activated_true = activated.unwrap_or(rows),
                            "witness batches collected"
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

        // Ensure every proof-plan node has an entry, even if no witness plans were
        // declared, so downstream consumers can rely on presence.
        for node in &nodes {
            by_id.entry(node_ptr_id(node)).or_default();
        }

        let mut results_by_node_id: HashMap<ProofPlanNodeId, HashMap<String, Vec<RecordBatch>>> =
            HashMap::with_capacity(nodes.len());
        for node in nodes {
            let node_id = node.node_id();
            let ptr_id = node_ptr_id(&node);
            let entry = by_id.remove(&ptr_id).unwrap_or_default();
            results_by_node_id.insert(node_id, entry);
        }

        Ok(Self::new(results_by_node_id))
    }
}

impl<'a> IntoIterator for &'a WitnessGraph {
    type Item = (&'a ProofPlanNodeId, &'a HashMap<String, Vec<RecordBatch>>);
    type IntoIter =
        std::collections::hash_map::Iter<'a, ProofPlanNodeId, HashMap<String, Vec<RecordBatch>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl IntoIterator for WitnessGraph {
    type Item = (ProofPlanNodeId, HashMap<String, Vec<RecordBatch>>);
    type IntoIter =
        std::collections::hash_map::IntoIter<ProofPlanNodeId, HashMap<String, Vec<RecordBatch>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

struct WitnessNodesDebug<'a> {
    inner: &'a HashMap<ProofPlanNodeId, HashMap<String, Vec<RecordBatch>>>,
}

impl<'a> fmt::Debug for WitnessNodesDebug<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (node_id, batches_by_label) in self.inner.iter() {
            map.entry(
                &NodeIdDebug { node_id },
                &WitnessLabelsDebug {
                    inner: batches_by_label,
                },
            );
        }
        map.finish()
    }
}

struct WitnessLabelsDebug<'a> {
    inner: &'a HashMap<String, Vec<RecordBatch>>,
}

impl<'a> fmt::Debug for WitnessLabelsDebug<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (label, batches) in self.inner.iter() {
            map.entry(label, &WitnessBatchSummary { batches });
        }
        map.finish()
    }
}

struct WitnessBatchSummary<'a> {
    batches: &'a [RecordBatch],
}

impl<'a> fmt::Debug for WitnessBatchSummary<'a> {
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
    node_id: &'a ProofPlanNodeId,
}

impl<'a> fmt::Debug for NodeIdDebug<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&describe_node_id(self.node_id))
    }
}

pub(crate) fn plan_label(node: &Arc<dyn ProofPlan>) -> &'static str {
    match node.node_id() {
        ProofPlanNodeId::LogicalPlan(_) => "LogicalPlan",
        ProofPlanNodeId::Expr(_) => "Expr",
    }
}

/// Stable-ish identifier for a node based on its vtable pointer, used to join
/// asynchronous witness results back to the plan shape.
fn node_ptr_id(p: &Arc<dyn ProofPlan>) -> usize {
    let data_ptr = &**p as *const dyn ProofPlan as *const ();
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

pub mod display;
#[cfg(test)]
pub mod tests;

use std::{collections::HashMap, sync::Arc};

use datafusion::{
    arrow::{
        array::{Array, BooleanArray},
        record_batch::RecordBatch,
    },
    error::Result as DFResult,
    prelude::SessionContext,
};

use crate::ra_proof_plan::{logical_plan_nodes::TableScanNode, ProofPlan, ProofPlanNodeType};

use futures::{
    future::{try_join_all, BoxFuture},
    FutureExt,
};
use tracing::{debug, trace};

/// Tree-structured witness node mirroring the ProofPlan shape.
/// Each node contains its own materialized result and its children’s witnesses.
pub struct WitnessNode {
    pub node: Arc<dyn ProofPlan>,
    pub results: HashMap<String, Vec<RecordBatch>>,
    pub children: Vec<WitnessNode>,
}

impl WitnessNode {
    /// Return the batches collected for a specific witness label, if present.
    pub fn batches_for(&self, label: &str) -> Option<&Vec<RecordBatch>> {
        self.results.get(label)
    }

    /// Heuristic to pick a "primary" result set for display or summary stats.
    /// Prefers `output_plan`, falls back to `relative_output`, then any
    /// entry.
    pub fn primary_batches(&self) -> Option<&Vec<RecordBatch>> {
        self.batches_for("output_plan")
            .or_else(|| self.batches_for("relative_output"))
            .or_else(|| self.results.values().next())
    }
}

pub(crate) fn plan_label(node: &Arc<dyn ProofPlan>) -> &'static str {
    match node.node_type() {
        ProofPlanNodeType::LogicalPlan(_) => "LogicalPlan",
        ProofPlanNodeType::Expr(_) => "Expr",
        ProofPlanNodeType::None => "Unknown",
    }
}

/// Execute the proof tree and assemble a witness tree mirroring the ProofPlan
/// shape. All witness-generation logical plans are executed in parallel.
#[tracing::instrument(name = "proof_to_witness_plan", skip(ctx, root))]
pub async fn proof_to_witness_plan(
    ctx: &SessionContext,
    root: Arc<dyn ProofPlan>,
) -> DFResult<WitnessNode> {
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

    // Make sure nodes without witness plans still have an entry so the tree can
    // be rebuilt faithfully.
    for node in &nodes {
        by_id.entry(node_ptr_id(node)).or_default();
    }

    fn build(
        node: &Arc<dyn ProofPlan>,
        by_id: &mut HashMap<usize, HashMap<String, Vec<RecordBatch>>>,
    ) -> WitnessNode {
        let id = node_ptr_id(node);
        let results = by_id.remove(&id).unwrap_or_default();
        let children = node
            .children()
            .into_iter()
            .map(|c| build(c, by_id))
            .collect();
        WitnessNode {
            node: Arc::clone(node),
            results,
            children,
        }
    }

    Ok(build(&root, &mut by_id))
}

// Tree traversal helpers for WitnessNode, post-order (children then parent)
pub fn append_sorted_descendants<'a>(node: &'a WitnessNode, out: &mut Vec<&'a WitnessNode>) {
    for child in &node.children {
        append_sorted_descendants(child, out);
    }
    out.push(node);
}

pub fn sorted_descendants<'a>(root: &'a WitnessNode) -> Vec<&'a WitnessNode> {
    let mut v: Vec<&'a WitnessNode> = Vec::new();
    append_sorted_descendants(root, &mut v);
    v
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

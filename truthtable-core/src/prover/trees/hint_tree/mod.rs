use crate::proof_nodes::prover::ProverPlanNode;
pub mod display;
#[cfg(test)]
pub mod tests;
use crate::proof_nodes::{id::NodeId, lps::prover::ProverTableScanNode};
use arithmetic::ACTIVATOR_COL_NAME;
use indexmap::IndexMap;
use std::{fmt, sync::Arc};

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{
    arrow::{
        array::{Array, ArrayRef, BooleanArray, BooleanBuilder},
        compute::concat,
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    },
    error::{DataFusionError, Result as DFResult},
    prelude::SessionContext,
};

use futures::{
    FutureExt,
    future::{BoxFuture, try_join_all},
};
use tracing::{debug, instrument, trace};

use crate::prover::trees::proof_tree::ProverProofTree;

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
    arena: IndexMap<NodeId, IndexMap<String, Vec<RecordBatch>>>,
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
            .field("num_nodes", &self.arena.len())
            .field("nodes", &HintNodesDebug { inner: &self.arena })
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
        arena: IndexMap<NodeId, IndexMap<String, Vec<RecordBatch>>>,
    ) -> Self {
        Self {
            arena,
            inner_proof_tree: proof_tree,
        }
    }

    pub fn len(&self) -> usize {
        self.arena.len()
    }

    pub fn is_empty(&self) -> bool {
        self.arena.is_empty()
    }

    /// Return the batches collected for a specific hint label at the
    /// requested proof-tree node, if present.
    pub fn batches_for(&self, node_id: &NodeId, label: &str) -> Option<&Vec<RecordBatch>> {
        self.arena
            .get(node_id)
            .and_then(|by_label| by_label.get(label))
    }

    /// Heuristic to pick a "primary" result set for a proof-tree node. Prefers
    /// `output_tree`, falls back to `relative_output`, then any entry.
    pub fn primary_batches(&self, node_id: &NodeId) -> Option<&Vec<RecordBatch>> {
        self.batches_for(node_id, "output_tree")
            .or_else(|| self.batches_for(node_id, "relative_output"))
            .or_else(|| self.arena.get(node_id).and_then(|m| m.values().next()))
    }

    pub fn results_for(&self, node_id: &NodeId) -> Option<&IndexMap<String, Vec<RecordBatch>>> {
        self.arena.get(node_id)
    }

    pub fn proof_tree(&self) -> &ProverProofTree<F, MvPCS, UvPCS> {
        &self.inner_proof_tree
    }

    pub fn display_graphviz(&self) -> display::DisplayableProverHintTree<'_, F, MvPCS, UvPCS> {
        display::DisplayableProverHintTree::new(self)
    }

    pub fn arena(&self) -> &IndexMap<NodeId, IndexMap<String, Vec<RecordBatch>>> {
        &self.arena
    }

    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        ProverProofTree<F, MvPCS, UvPCS>,
        IndexMap<NodeId, IndexMap<String, Vec<RecordBatch>>>,
    ) {
        let ProverHintTree {
            arena,
            inner_proof_tree,
        } = self;
        (inner_proof_tree, arena)
    }

    /// Execute the proof tree and assemble a hint tree mirroring the
    /// proof-tree shape. All hint-generation logical plans are executed in
    /// parallel.
    #[instrument(level = "debug", skip_all)]
    pub async fn from_proof_tree(
        ctx: &SessionContext,
        proof_tree: ProverProofTree<F, MvPCS, UvPCS>,
    ) -> DFResult<Self> {
        todo!()
        // let nodes: Vec<_> = proof_tree.arena().values().cloned().collect();

        // #[allow(clippy::type_complexity)]
        // let mut futures: Vec<
        //     BoxFuture<'static, DFResult<(usize, String, Vec<RecordBatch>)>>,
        // > = Vec::new();

        // for node in &nodes {
        //     let trees = node.hint_dfs(&proof_tree);
        //     for (label, hint_plan) in trees {
        //         if let Some(projected_plan) = hint_plan.project_materialized() {
        //             let ctx = ctx.clone();
        //             let node = Arc::clone(node);
        //             let label_clone = label.clone();
        //             futures.push(
        //                 async move {
        //                     // Optimize and materialize the hint plan tied to this
        //                     // node/label pair.
        //                     debug!(
        //                         node = tree_label(&node),
        //                         tree_label = %label_clone,
        //                         "executing hint tree"
        //                     );
        //                     // let plan_with_filter =
        //                     // ensure_activator_filter(projected_plan.clone());
        //                     let optimized_plan = ctx.state().optimize(&projected_plan).unwrap();
        //                     let df = ctx.execute_logical_plan(optimized_plan).await?;
        //                     // Collect per-partition batches and flatten them in partition order
        //                     // so we keep a deterministic row ordering even when the executor
        //                     // runs partitions in parallel.
        //                     let mut batches = df
        //                         .collect_partitioned()
        //                         .await?
        //                         .into_iter()
        //                         .flatten()
        //                         .collect::<Vec<_>>();

        //                     batches = add_activator_and_pad_power_of_two(batches)?;

        //                     if label_clone == "output_tree"
        //                         && node
        //                             .as_any()
        //                             .downcast_ref::<ProverTableScanNode>()
        //                             .is_some()
        //                     {
        //                         let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
        //                         assert!(
        //                             rows != 0 && (rows & (rows - 1)) == 0,
        //                             "TableScan rows not power-of-two: {}",
        //                             rows
        //                         );
        //                     }

        //                     let (rows, cols, activated) = rows_cols_activated(&batches);
        //                     trace!(
        //                         node = tree_label(&node),
        //                         tree_label = %label_clone,
        //                         rows,
        //                         cols,
        //                         activated_true = activated.unwrap_or(rows),
        //                         "hint batches collected"
        //                     );

        //                     Ok((node_ptr_id(&node), label_clone, batches))
        //                 }
        //                 .boxed(),
        //             );
        //         }
        //     }
        // }

        // // Wait for all hint plans to finish and bucket the batches by node id.
        // let results = try_join_all(futures).await?;

        // let mut by_id: IndexMap<usize, IndexMap<String, Vec<RecordBatch>>> = IndexMap::new();
        // for (id, label, batches) in results {
        //     by_id.entry(id).or_default().insert(label, batches);
        // }

        // // Guarantee every proof-tree node has a map entry, even if it produced no
        // // hints, so consumers always find a placeholder structure.
        // for node in &nodes {
        //     by_id.entry(node_ptr_id(node)).or_default();
        // }

        // let mut results_by_node_id: IndexMap<NodeId, IndexMap<String, Vec<RecordBatch>>> =
        //     IndexMap::with_capacity(nodes.len());
        // for node in nodes {
        //     let node_id = node.node_id();
        //     let ptr_id = node_ptr_id(&node);
        //     let mut entry = by_id.shift_remove(&ptr_id).unwrap_or_default();
        //     if entry.len() <= 1 {
        //         results_by_node_id.insert(node_id, entry);
        //         continue;
        //     }

        //     let mut ordered_entry = IndexMap::with_capacity(entry.len());
        //     let hint_plan_order = node.hint_dfs(&proof_tree);
        //     for label in hint_plan_order.keys() {
        //         if let Some(batches) = entry.shift_remove(label) {
        //             ordered_entry.insert(label.clone(), batches);
        //         }
        //     }
        //     // Preserve any additional labels that might have been produced but not present
        //     // in the plan order (e.g. dynamic hints) in their existing insertion order.
        //     for (label, batches) in entry {
        //         ordered_entry.insert(label, batches);
        //     }

        //     results_by_node_id.insert(node_id, ordered_entry);
        // }

        // Ok(Self::new(proof_tree, results_by_node_id))
    }
}

impl<'a, F, MvPCS, UvPCS> IntoIterator for &'a ProverHintTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    type Item = (&'a NodeId, &'a IndexMap<String, Vec<RecordBatch>>);
    type IntoIter = indexmap::map::Iter<'a, NodeId, IndexMap<String, Vec<RecordBatch>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.arena.iter()
    }
}

impl<F, MvPCS, UvPCS> IntoIterator for ProverHintTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    type Item = (NodeId, IndexMap<String, Vec<RecordBatch>>);
    type IntoIter = indexmap::map::IntoIter<NodeId, IndexMap<String, Vec<RecordBatch>>>;

    fn into_iter(self) -> Self::IntoIter {
        let ProverHintTree { arena, .. } = self;
        arena.into_iter()
    }
}

struct HintNodesDebug<'a> {
    inner: &'a IndexMap<NodeId, IndexMap<String, Vec<RecordBatch>>>,
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
    inner: &'a IndexMap<String, Vec<RecordBatch>>,
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
    node: &Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
) -> &'static str
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    match node.node_id() {
        NodeId::LP(_) => "LogicalPlan",
        NodeId::Expr(_) => "Expr",
        NodeId::None => "None",
    }
}

/// Stable-ish identifier for a node based on its vtable pointer, used to join
/// asynchronous hint results back to the tree shape.
fn node_ptr_id<F, MvPCS, UvPCS>(p: &Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>) -> usize {
    let data_ptr = &**p as *const dyn ProverPlanNode<F, MvPCS, UvPCS> as *const ();
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
        .find_map(|b| b.schema().index_of(ACTIVATOR_COL_NAME).ok());
    if let Some(_idx) = activator_idx {
        let mut count_true = 0usize;
        for b in batches {
            if let Ok(i) = b.schema().index_of(ACTIVATOR_COL_NAME) {
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

fn add_activator_and_pad_power_of_two(batches: Vec<RecordBatch>) -> DFResult<Vec<RecordBatch>> {
    if batches.is_empty() {
        return Ok(Vec::new());
    }

    let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    if total_rows == 0 || total_rows.is_power_of_two() {
        return Ok(batches);
    }

    let mut new_batches = Vec::new();
    let mut processed_rows = 0usize;
    let mut last_nonempty: Option<RecordBatch> = None;
    let mut out_schema: Option<Arc<Schema>> = None;
    let mut activator_index: Option<usize> = None;

    for batch in batches {
        let batch_rows = batch.num_rows();
        if out_schema.is_none() {
            let mut fields: Vec<Field> = batch
                .schema()
                .fields()
                .iter()
                .map(|f| (**f).clone())
                .collect();
            if !fields.iter().any(|f| f.name() == ACTIVATOR_COL_NAME) {
                fields.push(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false));
            }
            let schema = Arc::new(Schema::new(fields));
            activator_index = schema
                .fields()
                .iter()
                .position(|f| f.name() == ACTIVATOR_COL_NAME);
            out_schema = Some(schema);
        }

        let schema = Arc::clone(out_schema.as_ref().unwrap());
        let act_idx = activator_index.expect("activator field missing");

        let mut cols: Vec<ArrayRef> = batch.columns().to_vec();
        if cols.len() != schema.fields().len() {
            // Original batch had no activator; append one filled with `true`.
            let mut builder = BooleanBuilder::with_capacity(batch_rows);
            for _ in 0..batch_rows {
                builder.append_value(true);
            }
            cols.insert(act_idx, Arc::new(builder.finish()));
        }

        let new_batch = RecordBatch::try_new(schema.clone(), cols)?;
        if batch_rows > 0 {
            processed_rows += batch_rows;
            last_nonempty = Some(new_batch.clone());
        }
        new_batches.push(new_batch);
    }

    if processed_rows == 0 {
        return Ok(new_batches);
    }

    if !processed_rows.is_power_of_two() {
        let target = processed_rows.next_power_of_two();
        let pad = target - processed_rows;
        let last_batch = last_nonempty.expect("expected non-empty batch");
        let schema = out_schema.unwrap();
        let act_idx = activator_index.expect("activator index missing");
        let last_row_idx = last_batch.num_rows() - 1;

        let mut pad_cols: Vec<ArrayRef> = Vec::with_capacity(schema.fields().len());
        for (col_idx, field) in schema.fields().iter().enumerate() {
            if col_idx == act_idx && field.name() == ACTIVATOR_COL_NAME {
                let mut builder = BooleanBuilder::with_capacity(pad);
                for _ in 0..pad {
                    builder.append_value(false);
                }
                pad_cols.push(Arc::new(builder.finish()));
            } else {
                let single = last_batch.column(col_idx).slice(last_row_idx, 1);
                let repeats: Vec<&dyn Array> = (0..pad).map(|_| single.as_ref()).collect();
                let concatenated =
                    concat(&repeats).map_err(|e| DataFusionError::ArrowError(e, None))?;
                pad_cols.push(concatenated);
            }
        }

        let pad_batch = RecordBatch::try_new(schema.clone(), pad_cols)?;
        new_batches.push(pad_batch);
    }

    Ok(new_batches)
}

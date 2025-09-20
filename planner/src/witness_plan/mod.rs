pub mod display;
#[cfg(test)]
pub mod tests;

use std::{future::Future, pin::Pin, sync::Arc};

use datafusion::{
    arrow::{
        array::{Array, ArrayRef, BooleanArray},
        compute::concat as arrow_concat,
        record_batch::RecordBatch,
    },
    common::tree_node::{Transformed, TreeNode},
    error::Result as DFResult,
    logical_expr::{self as df, ExprSchemable},
    prelude::SessionContext,
};

use crate::ra_proof_plan::{
    nodes::{FilterNode, ProjectionNode, TableScanNode},
    RAProofPlan,
};

use futures::future::try_join_all;
use std::collections::HashMap;
use tracing::{debug, instrument, trace};

/// Tree-structured witness node mirroring the RAProofPlan shape.
/// Each node contains its own materialized result and its children’s witnesses.
pub struct WitnessNode {
    pub node: Arc<dyn RAProofPlan>,
    pub result: Vec<RecordBatch>,
    pub children: Vec<WitnessNode>,
}

/// Execute the proof tree and assemble a witness tree mirroring the RAProofPlan
/// shape. Uses a sequential, inputs-first strategy so parents can consume
/// materialized child outputs via temporary MemTables.
#[tracing::instrument(name = "proof_to_witness_tree", skip(ctx, root))]
pub async fn proof_to_witness_tree(
    ctx: &SessionContext,
    root: Arc<dyn RAProofPlan>,
    is_parallel: bool,
) -> DFResult<WitnessNode> {
    if is_parallel {
        return proof_to_witness_tree_par(ctx, root).await;
    }
    proof_to_witness_tree_seq(ctx, root).await
}

/// Sequential execution building the witness tree by feeding materialized child
/// outputs to their parents via temporary MemTables.
async fn proof_to_witness_tree_seq(
    ctx: &SessionContext,
    root: Arc<dyn RAProofPlan>,
) -> DFResult<WitnessNode> {
    let mut temp_tables: HashMap<usize, String> = HashMap::new();

    fn exec_node<'a>(
        ctx: &'a SessionContext,
        node: Arc<dyn RAProofPlan>,
        temp_tables: &'a mut HashMap<usize, String>,
    ) -> Pin<Box<dyn Future<Output = DFResult<WitnessNode>> + 'a>> {
        Box::pin(async move {
            // Execute children first
            let mut children_nodes = Vec::new();
            for child in node.children() {
                let cn = exec_node(ctx, Arc::clone(child), temp_tables).await?;
                children_nodes.push(cn);
            }

            let id = node_ptr_id(&node);
            let mut batches: Vec<RecordBatch> = Vec::new();

            if let Some(ts) = node.as_any().downcast_ref::<TableScanNode>() {
                let df = ctx.execute_logical_plan(ts.relative_plan()).await?;
                batches = df.collect().await?;
                let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
                assert!(
                    rows != 0 && (rows & (rows - 1)) == 0,
                    "TableScan rows not power-of-two: {}",
                    rows
                );
                debug!(node = node.name(), rows, "scan collected (sequential)");

                let single = unify_batches(&batches)?;
                let table_name = format!("wp_{}", id);
                let _ = ctx.register_batch(&table_name, single)?;
                temp_tables.insert(id, table_name);
            } else if let Some(p) = node.as_any().downcast_ref::<ProjectionNode>() {
                let child = node.children()[0];
                let child_id = node_ptr_id(child);
                let table = temp_tables.get(&child_id).expect("child output missing");
                let input_df = ctx.table(table).await?;
                let input_schema = input_df.logical_plan().schema();
                let mut exprs: Vec<df::Expr> =
                    p.expr.clone().into_iter().map(unqualify_expr).collect();
                if input_schema
                    .field_with_unqualified_name("activator")
                    .is_ok()
                {
                    let projects_activator = exprs.iter().any(|e| match e {
                        df::Expr::Column(c) => c.name == "activator",
                        df::Expr::Alias(a) => a.name == "activator",
                        df::Expr::Wildcard { .. } => true,
                        _ => false,
                    });
                    if !projects_activator {
                        exprs.push(df::col("activator"));
                    }
                }
                let out_df = input_df.select(exprs)?;
                batches = out_df.collect().await?;
                let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
                debug!(
                    node = node.name(),
                    rows, "projection collected (sequential)"
                );

                let single = unify_batches(&batches)?;
                let table_name = format!("wp_{}", id);
                let _ = ctx.register_batch(&table_name, single)?;
                temp_tables.insert(id, table_name);
            } else if let Some(f) = node.as_any().downcast_ref::<FilterNode>() {
                let child = node.children()[0];
                let child_id = node_ptr_id(child);
                let table = temp_tables.get(&child_id).expect("child output missing");
                let input_df = ctx.table(table).await?;

                let input_plan = input_df.logical_plan();
                let schema = input_plan.schema().clone();
                let activator_field = schema
                    .field_with_unqualified_name("activator")
                    .unwrap_or_else(|_| panic!("'activator' column not found in input schema"));
                let activator_dtype = activator_field.data_type().clone();

                let pred = unqualify_expr(f.predicate.clone());
                let try_bool_and = df::and(df::col("activator"), pred.clone());
                let new_activator = if try_bool_and.get_type(schema.as_ref()).is_ok() {
                    try_bool_and.alias("activator")
                } else {
                    let one = df::lit(1)
                        .cast_to(&activator_dtype, schema.as_ref())
                        .unwrap();
                    let zero = df::lit(0)
                        .cast_to(&activator_dtype, schema.as_ref())
                        .unwrap();
                    let mask = df::when(pred.clone(), one.clone())
                        .otherwise(zero.clone())
                        .unwrap();
                    let try_bit_and = df::bitwise_and(df::col("activator"), mask.clone());
                    if try_bit_and.get_type(schema.as_ref()).is_ok() {
                        try_bit_and.alias("activator")
                    } else {
                        df::when(pred.clone(), df::col("activator"))
                            .otherwise(zero)
                            .unwrap()
                            .alias("activator")
                    }
                };

                let mut proj_exprs: Vec<df::Expr> = Vec::with_capacity(schema.fields().len());
                for field in schema.fields() {
                    if field.name() == "activator" {
                        proj_exprs.push(new_activator.clone());
                    } else {
                        proj_exprs.push(df::col(field.name()));
                    }
                }

                let out_df = input_df.select(proj_exprs)?;
                batches = out_df.collect().await?;
                let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
                debug!(node = node.name(), rows, "filter collected (sequential)");

                let single = unify_batches(&batches)?;
                let table_name = format!("wp_{}", id);
                let _ = ctx.register_batch(&table_name, single)?;
                temp_tables.insert(id, table_name);
            } else {
                let df = ctx.execute_logical_plan(node.relative_plan()).await?;
                batches = df.collect().await?;
                let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
                debug!(
                    node = node.name(),
                    rows, "generic node collected (sequential)"
                );
                let single = unify_batches(&batches)?;
                let table_name = format!("wp_{}", id);
                let _ = ctx.register_batch(&table_name, single)?;
                temp_tables.insert(id, table_name);
            }

            Ok(WitnessNode {
                node,
                result: batches,
                children: children_nodes,
            })
        })
    }

    exec_node(ctx, root, &mut temp_tables).await
}

/// Parallel execution: evaluate each node's absolute plan independently and
/// assemble a tree from the collected results.
async fn proof_to_witness_tree_par(
    ctx: &SessionContext,
    root: Arc<dyn RAProofPlan>,
) -> DFResult<WitnessNode> {
    // Collect all nodes (post-order) from the proof plan
    fn collect(node: &Arc<dyn RAProofPlan>, out: &mut Vec<Arc<dyn RAProofPlan>>) {
        for c in node.children() {
            collect(c, out);
        }
        out.push(Arc::clone(node));
    }
    let mut nodes = Vec::new();
    collect(&root, &mut nodes);

    // Execute absolute plans concurrently
    let futures = nodes.iter().map(|n| {
        let ctx = ctx.clone();
        let node = Arc::clone(n);
        async move {
            let plan = node.absolute_plan();
            debug!(node = node.name(), "executing absolute (parallel)");
            let df = ctx.execute_logical_plan(plan).await?;
            let batches = df.collect().await?;
            let (rows, cols, activated) = rows_cols_activated(&batches);
            if node.name() == "TableScanNode" {
                assert!(
                    rows != 0 && (rows & (rows - 1)) == 0,
                    "TableScan rows not power-of-two: {}",
                    rows
                );
            }
            trace!(
                node = node.name(),
                rows,
                cols,
                activated_true = activated.unwrap_or(rows),
                "collected (parallel)"
            );
            Ok::<(usize, Vec<RecordBatch>), datafusion::error::DataFusionError>((
                node_ptr_id(&node),
                batches,
            ))
        }
    });
    let results: Vec<(usize, Vec<RecordBatch>)> = try_join_all(futures).await?;
    let mut by_id: HashMap<usize, Vec<RecordBatch>> = HashMap::with_capacity(results.len());
    for (id, batches) in results {
        by_id.insert(id, batches);
    }

    // Assemble the witness tree using the proof tree shape and collected results
    fn build(
        node: &Arc<dyn RAProofPlan>,
        by_id: &mut HashMap<usize, Vec<RecordBatch>>,
    ) -> WitnessNode {
        let id = node_ptr_id(node);
        let result = by_id.remove(&id).unwrap_or_else(|| Vec::new());
        let children = node
            .children()
            .into_iter()
            .map(|c| build(c, by_id))
            .collect();
        WitnessNode {
            node: Arc::clone(node),
            result,
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

/// Concatenate multiple record batches into a single batch (column-wise
/// concat).
///
/// This helps us register a single `MemTable` per node for simple downstream
/// scans.
fn unify_batches(batches: &[RecordBatch]) -> DFResult<RecordBatch> {
    if batches.is_empty() {
        // Create an empty batch with no columns
        return Ok(RecordBatch::new_empty(Arc::new(
            datafusion::arrow::datatypes::Schema::empty(),
        )));
    }
    let schema = batches[0].schema();
    let num_cols = schema.fields().len();
    let mut cols: Vec<ArrayRef> = Vec::with_capacity(num_cols);
    for col_idx in 0..num_cols {
        let parts: Vec<&dyn datafusion::arrow::array::Array> =
            batches.iter().map(|b| b.column(col_idx).as_ref()).collect();
        let arr = if parts.len() == 1 {
            batches[0].column(col_idx).clone()
        } else {
            arrow_concat(&parts)?
        };
        cols.push(arr);
    }
    Ok(RecordBatch::try_new(schema.clone(), cols)?)
}

/// Stable-ish identifier for a node based on its vtable pointer, used to
/// create unique temp table names during sequential execution.
fn node_ptr_id(p: &Arc<dyn RAProofPlan>) -> usize {
    let data_ptr = &**p as *const dyn RAProofPlan as *const ();
    data_ptr as usize
}

// Rewrite an expression to drop any table qualifier from column references,
// so it can resolve against temp MemTables (which expose unqualified names).
fn unqualify_expr(expr: df::Expr) -> df::Expr {
    expr.transform(|e| {
        if let df::Expr::Column(c) = &e {
            // Recreate as unqualified column
            return Ok(Transformed::yes(df::col(&c.name)));
        }
        Ok(Transformed::no(e))
    })
    .unwrap()
    .data
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

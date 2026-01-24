use std::sync::Arc;

use ark_piop::SnarkBackend;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::prelude::DataFrame;
use datafusion_common::DataFusionError;
use tokio::runtime::RuntimeFlavor;
use tt_core::irs::nodes::{IsNode, Node};
use tt_core::irs::shared_ir::InitialIr;
use tt_core::irs::tree::Tree;

use super::ProofPlanOptimizerRule;

pub struct TruncateEmptyPayload;

impl<B: SnarkBackend> ProofPlanOptimizerRule<B> for TruncateEmptyPayload {
    fn name(&self) -> &'static str {
        "TruncateEmptyPayload"
    }

    fn optimize(&self, ir: InitialIr<B>) -> InitialIr<B> {
        let root = ir.tree().root().clone();
        if let Some(truncate_at) = find_first_empty_postorder(&root) {
            let tree = Tree::new_from_root(truncate_at);
            InitialIr::new_empty(tree)
        } else {
            ir
        }
    }
}

fn find_first_empty_postorder<B: SnarkBackend>(node: &Arc<Node<B>>) -> Option<Arc<Node<B>>> {
    for child in node.children() {
        if let Some(found) = find_first_empty_postorder(&child) {
            return Some(found);
        }
    }

    match node.as_ref() {
        Node::Plan(plan_node) => {
            let hint_df = plan_node.output();
            let batches = collect_blocking(hint_df.data_frame().clone())
                .expect("truncate empty payload collection should succeed");
            let row_count: usize = batches.iter().map(|batch| batch.num_rows()).sum();
            if row_count == 0 {
                return Some(node.clone());
            }
        }
        Node::Gadget(_) => {}
    }
    None
}

fn collect_blocking(df: DataFrame) -> datafusion_common::Result<Vec<RecordBatch>> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => match handle.runtime_flavor() {
            RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(df.collect()))
            }
            RuntimeFlavor::CurrentThread => {
                let df_clone = df.clone();
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| DataFusionError::Execution(e.to_string()))?;
                    rt.block_on(df_clone.collect())
                })
                .join()
                .map_err(|_| {
                    DataFusionError::Execution("dataframe collection thread panicked".to_string())
                })?
            }
            _ => tokio::task::block_in_place(|| handle.block_on(df.collect())),
        },
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| DataFusionError::Execution(e.to_string()))?;
            rt.block_on(df.collect())
        }
    }
}

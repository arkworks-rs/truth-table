use ark_piop::SnarkBackend;
use datafusion::arrow::array::{
    ArrayRef, BooleanArray, Int16Array, Int32Array, Int64Array, Int8Array, UInt16Array,
    UInt32Array, UInt64Array, UInt8Array,
};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::prelude::DataFrame;
use datafusion_common::DataFusionError;
use tokio::runtime::RuntimeFlavor;
use tracing::debug;
use tt_core::irs::nodes::{IsNode, Node};
use tt_core::irs::payloads::PayloadStructure;
use tt_core::irs::shared_ir::GadgetPlannedIr;

use arithmetic::ACTIVATOR_COL_NAME;

pub struct SimplifyNoDups;

impl<B: SnarkBackend> super::ProofPlanOptimizerRule<B> for SimplifyNoDups {
    fn name(&self) -> &'static str {
        "SimplifyNoDups"
    }

    fn optimize(&self, mut ir: GadgetPlannedIr<B>) -> GadgetPlannedIr<B> {
        let tree = ir.tree().clone();
        let arena = tree.arena().clone();
        for (id, node) in arena.iter() {
            let Node::Gadget(gadget) = node.as_ref() else {
                continue;
            };
            if gadget.name() != "NoDup" {
                continue;
            }
            let Some(PayloadStructure::GadgetPayload(mut payload)) =
                ir.payload_for_node(id).cloned()
            else {
                continue;
            };
            let Some(input_hint) = payload
                .get(tt_core::irs::nodes::gadget::utils::nodup::INPUT_LABEL)
                .cloned()
            else {
                continue;
            };

            let active_count = count_active_rows(input_hint.data_frame().clone());
            if active_count <= 1 {
                // Mark this NoDup as single-entry so we can skip heavy checks.
                payload.insert(
                    tt_core::irs::nodes::gadget::utils::nodup::SINGLE_ENTRY_LABEL.to_string(),
                    input_hint,
                );
                debug!("SimplifyNoDups: node={} single-entry", id);
                ir.set_payload_for_node(*id, Some(PayloadStructure::GadgetPayload(payload)));
            }
        }
        ir
    }
}

fn count_active_rows(df: DataFrame) -> usize {
    let batches = collect_blocking(df).expect("nodup active count should collect");
    batches
        .iter()
        .map(|batch| active_count_in_batch(batch))
        .sum()
}

fn active_count_in_batch(batch: &RecordBatch) -> usize {
    let Some(idx) = batch.schema().index_of(ACTIVATOR_COL_NAME).ok() else {
        return 0;
    };
    let array = batch.column(idx).clone();
    count_nonzero(array)
}

fn count_nonzero(array: ArrayRef) -> usize {
    if let Some(arr) = array.as_any().downcast_ref::<BooleanArray>() {
        return arr
            .iter()
            .filter(|val| matches!(val, Some(true)))
            .count();
    }
    if let Some(arr) = array.as_any().downcast_ref::<UInt8Array>() {
        return arr.iter().filter(|val| matches!(val, Some(v) if *v != 0)).count();
    }
    if let Some(arr) = array.as_any().downcast_ref::<UInt16Array>() {
        return arr.iter().filter(|val| matches!(val, Some(v) if *v != 0)).count();
    }
    if let Some(arr) = array.as_any().downcast_ref::<UInt32Array>() {
        return arr.iter().filter(|val| matches!(val, Some(v) if *v != 0)).count();
    }
    if let Some(arr) = array.as_any().downcast_ref::<UInt64Array>() {
        return arr.iter().filter(|val| matches!(val, Some(v) if *v != 0)).count();
    }
    if let Some(arr) = array.as_any().downcast_ref::<Int8Array>() {
        return arr.iter().filter(|val| matches!(val, Some(v) if *v != 0)).count();
    }
    if let Some(arr) = array.as_any().downcast_ref::<Int16Array>() {
        return arr.iter().filter(|val| matches!(val, Some(v) if *v != 0)).count();
    }
    if let Some(arr) = array.as_any().downcast_ref::<Int32Array>() {
        return arr.iter().filter(|val| matches!(val, Some(v) if *v != 0)).count();
    }
    if let Some(arr) = array.as_any().downcast_ref::<Int64Array>() {
        return arr.iter().filter(|val| matches!(val, Some(v) if *v != 0)).count();
    }
    0
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

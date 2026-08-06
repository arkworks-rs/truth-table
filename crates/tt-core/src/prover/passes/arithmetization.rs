use arithmetic::table::ArithTable;
use ark_ff::PrimeField;
use ark_piop::SnarkBackend;
use ark_piop::arithmetic::mat_poly::mle::MLE;
use datafusion::arrow::compute::concat_batches;
use datafusion::arrow::datatypes::{Field, FieldRef, Schema};
use indexmap::IndexMap;
use std::sync::Arc;

use crate::irs::nodes::IsNode;
use crate::{
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
    },
    prover::payloads::{ArithPayload, MaterializedPayload, MaterializedTable},
};
/// An arithmetization pass that arithmetizes the prover's materialized in-memory tables
///
/// This pass converts an IR with materialized in-memory tables into an IR with arithmetized tables, meaning that each column is encoded and represented as multilinear extensions (MLEs) over a finite field.
pub struct ArithmetizationPass<B>(std::marker::PhantomData<B>);

impl<B> ArithmetizationPass<B> {
    pub fn new() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<B> Default for ArithmetizationPass<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B> LocalPass<B, MaterializedPayload, ArithPayload<B::F>> for ArithmetizationPass<B>
where
    B: SnarkBackend,
{
    fn transform(
        &self,
        node: &Node<B>,
        _id: NodeId,
        payload: Option<&MaterializedPayload>,
    ) -> Option<ArithPayload<B::F>> {
        // Side-domain string columns are gated by the workspace-level
        // `CHAR_LEVEL_SIDE_POLYS_ENABLED` toggle AND restricted to base
        // tables (TableScan). The workspace toggle is currently off so this
        // whole path is inert; when we flip it on for string PIOPs, the
        // TableScan restriction still applies — intermediate operators
        // denormalize string columns across join fan-outs, which would
        // produce char-level polys sized to (joined_rows × avg_len) and
        // blow past both the SRS ceiling and available memory.
        let emit_side = node.name() == "TableScan"
            && arithmetic::encoding::CHAR_LEVEL_SIDE_POLYS_ENABLED;
        match payload? {
            MaterializedPayload::PlanPayload(mat) => {
                let arithmetized_table = arithmetize_materialized_table(mat, emit_side);
                tracing::debug!( node = %node.name(), typ= "plan", num_cols= arithmetized_table.num_total_cols(), log_size= arithmetized_table.log_size(), side_cols= arithmetized_table.side_cols().len(), "Arithmetized");
                Some(ArithPayload::PlanPayload(arithmetized_table))
            }
            MaterializedPayload::GadgetPayload(map) => {
                let mut out = IndexMap::new();
                for (k, mat) in map {
                    let arithmetized_table = arithmetize_materialized_table(mat, emit_side);
                    tracing::debug!( node = %node.name(), typ= "plan", key = %k, num_cols= arithmetized_table.num_total_cols(), log_size= arithmetized_table.log_size(), side_cols= arithmetized_table.side_cols().len(), "Arithmetized");
                    out.insert(k.clone(), arithmetized_table);
                }
                Some(ArithPayload::GadgetPayload(out))
            }
        }
    }

    fn order(&self) -> crate::irs::ir::PassOrder {
        crate::irs::ir::PassOrder::PostOrder
    }

    fn name(&self) -> &'static str {
        "Prover Arithmetization"
    }
}

pub fn arithmetize_materialized_table<F: PrimeField>(
    mat: &MaterializedTable,
    emit_side_segments: bool,
) -> ArithTable<F> {
    let batches = mat
        .batches()
        .expect("failed to read batches from materialized table");
    if batches.is_empty() {
        return ArithTable::new(None, IndexMap::new(), 0);
    }

    let schema_ref = batches[0].schema();
    let batch_refs: Vec<&datafusion::arrow::record_batch::RecordBatch> = batches.iter().collect();
    let combined_batch = concat_batches(&schema_ref, batch_refs)
        .expect("failed to concatenate record batches for arithmetization");

    let total_rows = combined_batch.num_rows();
    assert!(
        total_rows.is_power_of_two(),
        "Arithmetized tables must have power-of-two number of rows, got {}",
        total_rows
    );
    let log_vars = total_rows.trailing_zeros() as usize;
    let num_total_cols = schema_ref.fields().len();

    // Row-domain segments per source column. Side-domain segments are split
    // out into `side_segments_by_col` below and assembled into ArithSideCol
    // entries after row encoding completes. Side segments carry native small
    // ints (bytes or u32) so the in-memory side-col storage stays much
    // smaller than the field-element form.
    //
    // The row-domain path carries `EncodedBacking<F>` — the native-typed
    // backing chosen by the encoder (bool → Bits, u8 → U8s, non-negative
    // i32 → U32s, …). No `Vec<F>` materialization happens here for
    // compressible columns; each backing is handed straight to
    // `MLE::from_*` at the tracker boundary below.
    let mut row_segments_by_col: Vec<
        Vec<(FieldRef, arithmetic::encoding::EncodedBacking<F>)>,
    > = Vec::with_capacity(num_total_cols);
    let mut side_segments_by_col: Vec<
        Vec<(FieldRef, arithmetic::encoding::SideColData, usize /* active_len */)>,
    > = Vec::with_capacity(num_total_cols);

    for col_idx in 0..num_total_cols {
        let base_field = schema_ref.fields()[col_idx].clone();
        let encoded = arithmetic::encoding::encode_arrow_array_to_field::<F>(
            combined_batch.column(col_idx),
        )
        .expect("arrow encoding should succeed");

        let mut row_for_col: Vec<(FieldRef, arithmetic::encoding::EncodedBacking<F>)> = Vec::new();
        let mut side_for_col: Vec<(FieldRef, arithmetic::encoding::SideColData, usize)> =
            Vec::new();
        for segment in encoded {
            let field_ref = if segment.suffix.is_empty() {
                base_field.clone()
            } else {
                let mut field = Field::new(
                    format!("{}{}", base_field.name(), segment.suffix),
                    base_field.data_type().clone(),
                    base_field.is_nullable(),
                );
                if !base_field.metadata().is_empty() {
                    // Keep qualifiers on encoded segments so metadata-based matching still works.
                    field = field.with_metadata(base_field.metadata().clone());
                }
                Arc::new(field)
            };
            match segment.side {
                None => row_for_col.push((field_ref, segment.backing)),
                Some(info) => {
                    side_for_col.push((field_ref, info.data, info.active_len));
                }
            }
        }
        row_segments_by_col.push(row_for_col);
        side_segments_by_col.push(side_for_col);
    }

    let mut flattened_fields: Vec<FieldRef> = Vec::new();
    let mut flattened_backings: Vec<(FieldRef, arithmetic::encoding::EncodedBacking<F>)> =
        Vec::new();
    for column_group in row_segments_by_col {
        for (field_ref, backing) in column_group {
            flattened_fields.push(field_ref.clone());
            flattened_backings.push((field_ref, backing));
        }
    }

    // `into_mle` picks the correct `MLE::from_*` constructor per backing
    // variant — no `Vec<F>` intermediate. For a lineitem `u8`-typed column
    // this is a direct handoff of the arrow-shaped `Vec<u8>` into
    // `MLE::from_u8s`, saving ~2 GiB of transient heap per column at
    // 2^26 rows.
    let tracked_polys: IndexMap<FieldRef, Arc<MLE<F>>> = flattened_backings
        .into_iter()
        .map(|(field_ref, backing)| {
            let mle = Arc::new(backing.into_mle(log_vars));
            (field_ref, mle)
        })
        .collect();

    let schema_fields: Vec<Field> = flattened_fields
        .iter()
        .map(|field_ref| field_ref.as_ref().clone())
        .collect();
    let schema = Some(Schema::new(schema_fields));

    // Build side-column entries from raw bytes. ArithSideCol stores the
    // pow2-padded byte buffer plus `active_len`; commit/track passes
    // materialize transient `MLE<F>` views (for both data and the
    // contiguous-one activator) only at the moment of MSM / proof-binding.
    //
    // When `emit_side_segments` is false (intermediate operators), we skip
    // building these entirely — the raw bytes were already computed by the
    // encoder but we just drop them here. See caller for rationale.
    let mut side_cols: IndexMap<FieldRef, arithmetic::table::ArithSideCol> = IndexMap::new();
    if emit_side_segments {
        for column_group in side_segments_by_col {
            for (field_ref, data, active_len) in column_group {
                let side_size = data.len();
                assert!(
                    side_size.is_power_of_two(),
                    "side segment must be pow2-padded by encoder (field={}, len={})",
                    field_ref.name(),
                    side_size
                );
                let side_log_size = side_size.trailing_zeros() as usize;
                tracing::info!(
                    field = %field_ref.name(),
                    log_size = side_log_size,
                    active_len = active_len,
                    approx_f_mle_bytes = (1usize << side_log_size) * 32,
                    "side col emitted"
                );
                side_cols.insert(
                    field_ref,
                    arithmetic::table::ArithSideCol {
                        data,
                        log_size: side_log_size,
                        active_len,
                    },
                );
            }
        }
    }

    ArithTable::new_with_side_cols(schema, tracked_polys, log_vars, side_cols)
}

use arithmetic::table_oracle::{ArithTableOracle, TrackedTableOracle};
use ark_ff::{Field, Zero};
use ark_piop::{SnarkBackend, types::CommitmentBinding, verifier::ArgVerifier};
use datafusion::{
    arrow::datatypes::{FieldRef, Schema},
    datasource::{MemTable, TableProvider},
    prelude::SessionContext,
};
use datafusion_common::{DFSchema, DataFusionError};
use indexmap::IndexMap;

use crate::irs::nodes::IsNode;
use crate::{
    ctx_oracles::CtxOracles,
    errors::TTResult,
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
        payloads::{HintDFPayload, PayloadStructure},
    },
    prover::{
        passes::{
            arithmetization::arithmetize_materialized_table,
            materialization::pad_batches_to_num_rows_with_inactive_padding,
        },
        payloads::MaterializedTable,
    },
    verifier::payloads::TrackedPayload,
};
use std::cell::RefCell;
use std::sync::Arc;

const QUALIFIER_METADATA_KEY: &str = "tt.qualifier";
/// A tracking pass that tracks and commits the verifier's arithmetized tables
///
/// This pass converts an IR with arithmetized tables into an IR with tracked tables; i.e. tables that are commited and added to the transcript, therefore tracked by the SNARK verifier with an associated id. Note that this pass is stateful, as it requires access to the verifier instance to perform the tracking and committing.
pub struct TrackingPass<B: SnarkBackend> {
    verifier: RefCell<ArgVerifier<B>>,
    ctx_oracles: CtxOracles<B>,
    output_memtable: Option<Arc<MemTable>>,
}

impl<B: SnarkBackend> TrackingPass<B> {
    pub fn new(
        verifier: ArgVerifier<B>,
        ctx_oracles: CtxOracles<B>,
        output_memtable: Option<Arc<MemTable>>,
    ) -> Self {
        Self {
            verifier: RefCell::new(verifier),
            ctx_oracles,
            output_memtable,
        }
    }

    pub async fn finish(
        &self,
        tracked_ir: &mut crate::verifier::irs::TrackedIr<B>,
    ) -> TTResult<()> {
        let Some(output_memtable) = self.output_memtable.clone() else {
            return Ok(());
        };
        let root = tracked_ir.tree().root();
        if root.name() != "ResultCheck" {
            return Ok(());
        }

        let materialized = Self::materialized_table_from_memtable(output_memtable, None).await?;
        let arith_table = arithmetize_materialized_table::<B::F>(&materialized);
        let tracked_table = Self::track_output_table_oracle(&arith_table, &self.verifier);
        let gadget_id = root
            .children()
            .into_iter()
            .find(|child| child.name() == "ResultCheck")
            .map(|child| child.id())
            .ok_or_else(|| {
                DataFusionError::Internal("ResultCheck root missing gadget child".to_string())
            })?;
        let mut gadget_payload = match tracked_ir.payload_for_node(&gadget_id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(
            crate::irs::nodes::utils::result_check::OUTPUT_LABEL.to_string(),
            tracked_table,
        );
        tracked_ir.set_payload_for_node(
            gadget_id,
            Some(PayloadStructure::GadgetPayload(gadget_payload)),
        );
        Ok(())
    }
}

impl<B> LocalPass<B, HintDFPayload, TrackedPayload<B>> for TrackingPass<B>
where
    B: SnarkBackend,
{
    fn order(&self) -> crate::irs::ir::PassOrder {
        crate::irs::ir::PassOrder::PostOrder
    }
    fn transform(
        &self,
        node: &Node<B>,
        _id: NodeId,
        payload: Option<&HintDFPayload>,
    ) -> Option<TrackedPayload<B>> {
        // If there is no payload, do nothing
        let payload = payload?;
        match payload {
            // If the payload is a plan,
            HintDFPayload::PlanPayload(hint_df) => {
                if node.name() == "TableScan" {
                    let df_schema = hint_df.data_frame().schema();
                    let base_schema: Schema =
                        <DFSchema as AsRef<Schema>>::as_ref(df_schema).clone();
                    let oracle = infer_table_name_from_df_schema(df_schema)
                        .and_then(|name| self.ctx_oracles.table_oracle_by_name(&name))
                        .or_else(|| self.ctx_oracles.table_oracle_for_schema(&base_schema));
                    if let Some(oracle) = oracle {
                        // TableScan commitments are public input and must come from the oracle
                        // files, not from prover-selected proof commitments.
                        return track_hint_df_from_oracle(hint_df, oracle, &self.verifier)
                            .map(TrackedPayload::PlanPayload);
                    }
                    return track_hint_df(hint_df, &self.verifier).map(TrackedPayload::PlanPayload);
                }
                track_hint_df(hint_df, &self.verifier).map(TrackedPayload::PlanPayload)
            }
            HintDFPayload::GadgetPayload(map) => {
                let mut out = IndexMap::new();
                for (key, hint_df) in map.iter() {
                    if let Some(table) = track_hint_df(hint_df, &self.verifier) {
                        out.insert(key.clone(), table);
                    }
                }
                if out.is_empty() {
                    None
                } else {
                    Some(TrackedPayload::GadgetPayload(out))
                }
            }
        }
    }

    fn name(&self) -> &'static str {
        "Verifier Tracking"
    }
}

fn track_hint_df_from_oracle<B: SnarkBackend>(
    hint_df: &crate::irs::nodes::hints::HintDF,
    oracle: &ArithTableOracle<B>,
    verifier: &RefCell<ArgVerifier<B>>,
) -> Option<TrackedTableOracle<B>> {
    let df_schema_ref = hint_df.data_frame().schema();
    let base_schema: Schema = <DFSchema as AsRef<Schema>>::as_ref(df_schema_ref).clone();
    let qualified_fields = qualify_fields(df_schema_ref);
    let mut tracked_oracles: IndexMap<_, _> = IndexMap::new();
    let mut log_size = 0usize;

    let verifier = verifier.borrow_mut();
    for (field, should_mat) in hint_df.field_materialization_iter() {
        if !*should_mat {
            continue;
        }
        let qualified_field = qualified_fields
            .get(field)
            .cloned()
            .unwrap_or_else(|| field.clone());
        let commitment = oracle
            .commitments()
            .get(field)
            .cloned()
            .or_else(|| {
                oracle
                    .commitments()
                    .iter()
                    .find(|(oracle_field, _)| oracle_field.name() == field.name())
                    .map(|(_, commitment)| commitment.clone())
            })
            .unwrap_or_else(|| panic!("ctx_oracle missing commitment for field {}", field.name()));
        // Mirror prover-side external tracking for base-table commitments loaded
        // from context instead of from the proof's serialized commitment map.
        let tracked_oracle = verifier
            .track_mat_mv_com_with_binding(commitment, CommitmentBinding::External)
            .expect("verifier should track ctx_oracle commitment");
        if log_size == 0 {
            log_size = tracked_oracle.log_size();
        } else {
            debug_assert_eq!(log_size, tracked_oracle.log_size());
        }
        tracked_oracles.insert(qualified_field, tracked_oracle);
    }

    if tracked_oracles.is_empty() {
        None
    } else {
        let schema = Some(build_tracked_schema(
            &base_schema,
            tracked_oracles.keys(),
            oracle.schema_ref(),
        ));
        Some(TrackedTableOracle::new(schema, tracked_oracles, log_size))
    }
}

fn track_hint_df<B: SnarkBackend>(
    hint_df: &crate::irs::nodes::hints::HintDF,
    verifier: &RefCell<ArgVerifier<B>>,
) -> Option<TrackedTableOracle<B>> {
    let df_schema_ref = hint_df.data_frame().schema();
    let base_schema: Schema = <DFSchema as AsRef<Schema>>::as_ref(df_schema_ref).clone();
    let qualified_fields = qualify_fields(df_schema_ref);
    // Initialize some variables
    let mut tracked_oracles: IndexMap<_, _> = IndexMap::new();
    let mut log_size = 0usize;

    let mut verifier = verifier.borrow_mut();
    // Iterate through each field that needs materialization
    for (field, should_mat) in hint_df.field_materialization_iter() {
        if !*should_mat {
            continue;
        }
        let qualified_field = qualified_fields
            .get(field)
            .cloned()
            .unwrap_or_else(|| field.clone());
        // Use the next expected id so the verifier's tracker stays in sync with the proof
        let oracle = verifier
            .track_next_mv_com()
            .expect("verifier should track prover commitment by id");
        if log_size == 0 {
            log_size = oracle.log_size();
        } else {
            debug_assert_eq!(log_size, oracle.log_size());
        }
        tracked_oracles.insert(qualified_field, oracle);
    }
    // If there was no columns to be materialized, return None
    if tracked_oracles.is_empty() {
        None
    } else {
        let schema = Some(build_tracked_schema(
            &base_schema,
            tracked_oracles.keys(),
            None,
        ));
        Some(TrackedTableOracle::new(schema, tracked_oracles, log_size))
    }
}

fn build_tracked_schema<'a>(
    base_schema: &Schema,
    tracked_fields: impl Iterator<Item = &'a FieldRef>,
    oracle_schema: Option<&Schema>,
) -> Schema {
    // Keep field ordering exactly aligned with tracked_oracles keys, while
    // merging table-level metadata from hint-df + oracle schema.
    let mut metadata = base_schema.metadata().clone();
    if let Some(schema) = oracle_schema {
        metadata.extend(schema.metadata().clone());
    }
    let fields = tracked_fields
        .map(|f| f.as_ref().clone())
        .collect::<Vec<_>>();
    Schema::new_with_metadata(fields, metadata)
}

fn qualify_fields(df_schema: &DFSchema) -> IndexMap<FieldRef, FieldRef> {
    let mut out = IndexMap::new();
    for (qualifier, field) in df_schema.iter() {
        let mut updated = field.as_ref().clone();
        if updated.name() == arithmetic::ACTIVATOR_COL_NAME
            || updated.name() == arithmetic::ROW_ID_COL_NAME
        {
            out.insert(field.clone(), Arc::new(updated));
            continue;
        }
        if let Some(qualifier) = qualifier {
            // Mirror prover-side qualifier metadata to keep schemas aligned.
            let mut metadata = updated.metadata().clone();
            metadata.insert(QUALIFIER_METADATA_KEY.to_string(), qualifier.to_string());
            updated = updated.with_metadata(metadata);
        }
        out.insert(field.clone(), Arc::new(updated));
    }
    out
}

fn infer_table_name_from_df_schema(schema: &DFSchema) -> Option<String> {
    schema.iter().find_map(|(qualifier, field)| {
        if field.name() == arithmetic::ACTIVATOR_COL_NAME
            || field.name() == arithmetic::ROW_ID_COL_NAME
        {
            return None;
        }
        qualifier.as_ref().map(|qualifier| {
            let qualifier = qualifier.to_string();
            qualifier
                .rsplit('.')
                .next()
                .unwrap_or(&qualifier)
                .to_string()
        })
    })
}

impl<B: SnarkBackend> TrackingPass<B> {
    async fn materialized_table_from_memtable(
        mem_table: Arc<MemTable>,
        target_num_rows: Option<usize>,
    ) -> TTResult<MaterializedTable> {
        let ctx = SessionContext::new();
        let df = ctx.read_table(mem_table.clone())?;
        let mut batches = df.collect().await?;
        let schema = mem_table.schema();
        batches = pad_batches_to_num_rows_with_inactive_padding(
            schema.as_ref(),
            batches,
            target_num_rows,
        )?;
        let row_count = batches.iter().map(|batch| batch.num_rows()).sum();
        let rebuilt = MemTable::try_new(mem_table.schema(), vec![batches.clone()])
            .expect("memtable rebuild from collected batches should succeed");
        Ok(MaterializedTable::new_with_batches(
            rebuilt, row_count, batches,
        ))
    }

    fn track_output_table_oracle(
        arith_table: &arithmetic::table::ArithTable<B::F>,
        verifier: &RefCell<ArgVerifier<B>>,
    ) -> TrackedTableOracle<B> {
        let tracked_oracles = arith_table
            .polynomials()
            .iter()
            .map(|(field_ref, mle)| {
                let poly_evals = mle.evaluations();
                let num_vars = mle.num_vars();
                let oracle = ark_piop::verifier::structs::oracle::Oracle::new_multivariate(
                    arith_table.log_size(),
                    move |point| {
                        // Fast path: hypercube points (every coord is 0 or 1)
                        // become a direct array lookup — O(num_vars) instead of
                        // O(2^num_vars). result_check's verifier extracts res˜
                        // by querying at hypercube points, so this matters.
                        if let Some(idx) = hypercube_index(&point, num_vars) {
                            return Ok(poly_evals.get(idx).copied().unwrap_or_else(B::F::zero));
                        }
                        Ok(eval_mle_at_point(&poly_evals, num_vars, &point))
                    },
                );
                let tracked_oracle = verifier.borrow().track_base_oracle(oracle);
                (field_ref.clone(), tracked_oracle)
            })
            .collect();
        TrackedTableOracle::new(
            arith_table.schema(),
            tracked_oracles,
            arith_table.log_size(),
        )
    }
}

/// If every coordinate of `point` is exactly 0 or 1, return the integer index
/// it represents (little-endian bit order); otherwise `None`. Used to short-
/// circuit MLE evaluation at hypercube points to a direct array lookup.
fn hypercube_index<F: Field + Copy>(point: &[F], num_vars: usize) -> Option<usize> {
    let zero = F::zero();
    let one = F::one();
    let mut idx = 0usize;
    for i in 0..num_vars {
        let xi = point.get(i).copied().unwrap_or(zero);
        if xi == zero {
            // bit is 0
        } else if xi == one {
            idx |= 1 << i;
        } else {
            return None;
        }
    }
    Some(idx)
}

fn eval_mle_at_point<F: Field + Copy>(evaluations: &[F], num_vars: usize, point: &[F]) -> F {
    if num_vars == 0 {
        return evaluations.first().copied().unwrap_or_else(F::zero);
    }

    let mut layer = evaluations.to_vec();
    let one = F::one();
    for i in 0..num_vars {
        let x = point.get(i).copied().unwrap_or_else(F::zero);
        let mut next = Vec::with_capacity(layer.len() / 2);
        for chunk in layer.chunks_exact(2) {
            let low = chunk[0];
            let high = chunk[1];
            next.push(low * (one - x) + high * x);
        }
        layer = next;
    }
    layer[0]
}

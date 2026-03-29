use arithmetic::table::ArithTable;
use ark_ff::{Field, PrimeField};
use ark_ff::Zero;
use ark_piop::{verifier::ArgVerifier, SnarkBackend};
use ark_piop::structs::TrackerID;
use datafusion::{
    arrow::{
        array::{ArrayRef, BooleanArray},
        compute::{concat, concat_batches},
        datatypes::{DataType, Schema},
        record_batch::RecordBatch,
    },
    datasource::{MemTable, TableProvider},
    prelude::SessionContext,
};
use datafusion_common::DataFusionError;
use datafusion_common::ScalarValue;
use std::sync::Arc;
use tt_core::{
    ctx_oracles::CtxOracles,
    errors::TTResult,
    irs::nodes::IsNode,
    irs::payloads::PayloadStructure,
    irs::shared_ir::{EmptyIr, GadgetPlannedIr, OutputPlannedIr},
    prover::payloads::MaterializedTable,
    verifier::{
        irs::{
            GadgetReadyIr as VerifierGadgetReadyIr, TrackedIr as VerifierTrackedIr,
            VirtualizedIr as VerifierVirtualizedIr,
        },
        passes::{
            // reuse prover-side arithmetization logic so prover/verifier agree exactly
            // on the result-check output table encoding
            gadget_initialization::GadgetInitializationPass as VerifierGadgetInitializationPass,
            gadget_planning::GadgetPlanningPass as VerifierGadgetPlanningPass,
            output_planning::OutputPlanningPass as VerifierOutputPlanningPass,
            tracking::TrackingPass as VerifierTrackingPass, verify::VerifyPass,
            virtualization::VirtualizationPass as VerifierVirtualizationPass,
        },
    },
};
use tt_core::prover::passes::arithmetization::arithmetize_materialized_table;
use arithmetic::table_oracle::TrackedTableOracle;
use ark_piop::verifier::structs::oracle::Oracle;

use crate::{shared::TTSharedConfig, structs::TTProof};

const RESULT_CHECK_SRC_POLY_ID_PREFIX: &str = "result_check_src_poly_id";

pub struct VerifierIrStages<B: SnarkBackend> {
    pub initial: EmptyIr<B>,
    pub output_planned: OutputPlannedIr<B>,
    pub gadget_planned: GadgetPlannedIr<B>,
    pub tracked: VerifierTrackedIr<B>,
    pub virtualized: VerifierVirtualizedIr<B>,
    pub gadget_ready: VerifierGadgetReadyIr<B>,
}

pub struct TTVerifierConfig<B: SnarkBackend> {
    phantom: std::marker::PhantomData<B>,
}
impl<B: SnarkBackend> TTVerifierConfig<B> {
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }

    pub fn planning_pass(&self) -> VerifierOutputPlanningPass<B> {
        VerifierOutputPlanningPass::new()
    }
    pub fn gadget_planning_pass(
        &self,
        planned_ir: &OutputPlannedIr<B>,
    ) -> VerifierGadgetPlanningPass<B> {
        VerifierGadgetPlanningPass::new(planned_ir)
    }

    pub fn tracking_pass(
        &self,
        arg_verifier: ArgVerifier<B>,
        ctx_oracles: CtxOracles<B>,
    ) -> VerifierTrackingPass<B> {
        VerifierTrackingPass::new(arg_verifier, ctx_oracles)
    }
}

impl<B: SnarkBackend> Default for TTVerifierConfig<B> {
    fn default() -> Self {
        Self::new()
    }
}

/// Verifier configuration that bundles planner rules and context oracles.
pub struct TTVerifier<B: SnarkBackend> {
    verifier_config: TTVerifierConfig<B>,
    shared_config: TTSharedConfig<B>,
    arg_verifier: ArgVerifier<B>,
}

impl<B: SnarkBackend> TTVerifier<B> {
    pub fn new(
        verifier_config: TTVerifierConfig<B>,
        shared_config: TTSharedConfig<B>,
        arg_verifier: ArgVerifier<B>,
    ) -> Self {
        Self {
            verifier_config,
            shared_config,
            arg_verifier,
        }
    }

    pub fn verifier_config(&self) -> &TTVerifierConfig<B> {
        &self.verifier_config
    }
    pub fn shared_config(&self) -> &TTSharedConfig<B> {
        &self.shared_config
    }
    pub fn arg_verifier(&self) -> &ArgVerifier<B> {
        &self.arg_verifier
    }

    fn gadget_planned_ir_for_query(&self, _query: &str, proof: &TTProof<B>) -> GadgetPlannedIr<B> {
        let initial_ir = proof.optimized_ir().clone();
        let output_planned_ir =
            initial_ir.apply_local_pass_sequential(&self.verifier_config().planning_pass());
        let gadget_planned_ir = output_planned_ir.apply_local_pass_sequential(
            &self
                .verifier_config()
                .gadget_planning_pass(&output_planned_ir),
        );
        gadget_planned_ir
    }

    async fn verify_with_gadget_planned_ir(
        &self,
        proof: &TTProof<B>,
        gadget_planned_ir: &GadgetPlannedIr<B>,
        output_memtable: Option<Arc<MemTable>>,
    ) -> TTResult<()> {
        let snark_proof = proof.as_inner();
        let mut arg_verifier = self.arg_verifier().fork();
        arg_verifier.set_proof_ref(snark_proof);

        let verifier_tracking_pass = self.verifier_config().tracking_pass(
            arg_verifier.clone(),
            self.shared_config().ctx_oracles().clone(),
        );
        let mut tracked_ir = gadget_planned_ir.apply_local_pass_sequential(&verifier_tracking_pass);
        self.track_query_output(&mut tracked_ir, output_memtable, arg_verifier.clone())
            .await?;
        let verifier_virtualization_pass = VerifierVirtualizationPass::<B>::new(&tracked_ir);
        let virtualized_ir = tracked_ir.apply_local_pass_sequential(&verifier_virtualization_pass);

        let gadget_ir_view = VerifierVirtualizedIr::new(
            virtualized_ir.tree().clone(),
            virtualized_ir.payloads().clone(),
        );
        let gadget_initialization_pass =
            VerifierGadgetInitializationPass::<B>::new(gadget_ir_view, arg_verifier.clone());
        let gadget_ready_ir =
            virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);

        let verify_ir_view = VerifierGadgetReadyIr::new(
            gadget_ready_ir.tree().clone(),
            gadget_ready_ir.payloads().clone(),
        );
        let verify_pass = VerifyPass::<B>::new(arg_verifier.clone(), verify_ir_view);
        let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&verify_pass);
        verify_pass.take_result()?;

        arg_verifier.verify()?;
        Ok(())
    }

    pub async fn verify(&self, query: &str, proof: &TTProof<B>) -> TTResult<()> {
        // Fast path used by production verification and verifier benches.
        let gadget_planned_ir = self.gadget_planned_ir_for_query(query, proof);
        self.verify_with_gadget_planned_ir(proof, &gadget_planned_ir, None)
            .await
    }

    pub async fn verify_with_output(
        &self,
        query: &str,
        proof: &TTProof<B>,
        output_memtable: Arc<MemTable>,
    ) -> TTResult<()> {
        let gadget_planned_ir = self.gadget_planned_ir_for_query(query, proof);
        self.verify_with_gadget_planned_ir(proof, &gadget_planned_ir, Some(output_memtable))
            .await
    }

    pub async fn verify_with_preprocessed(
        &self,
        proof: &TTProof<B>,
        gadget_planned_ir: &GadgetPlannedIr<B>,
    ) -> TTResult<()> {
        self.verify_with_gadget_planned_ir(proof, gadget_planned_ir, None)
            .await
    }

    pub async fn verify_with_preprocessed_and_output(
        &self,
        proof: &TTProof<B>,
        gadget_planned_ir: &GadgetPlannedIr<B>,
        output_memtable: Arc<MemTable>,
    ) -> TTResult<()> {
        self.verify_with_gadget_planned_ir(proof, gadget_planned_ir, Some(output_memtable))
            .await
    }

    /// Run verifier planning for a query/proof pair (output + gadget planning only).
    ///
    /// This intentionally excludes tracking/virtualization/gadget-init/verify passes
    /// and excludes cryptographic verification.
    pub fn preprocess_query(&self, query: &str, proof: &TTProof<B>) -> GadgetPlannedIr<B> {
        self.gadget_planned_ir_for_query(query, proof)
    }

    pub async fn build_ir_stages(
        &self,
        query: &str,
        proof: &TTProof<B>,
    ) -> TTResult<(VerifierIrStages<B>, ArgVerifier<B>)> {
        self.build_ir_stages_with_output(query, proof, None).await
    }

    pub async fn build_ir_stages_with_output(
        &self,
        query: &str,
        proof: &TTProof<B>,
        output_memtable: Option<Arc<MemTable>>,
    ) -> TTResult<(VerifierIrStages<B>, ArgVerifier<B>)> {
        let snark_proof = proof.as_inner();
        let initial_ir = proof.optimized_ir().clone();
        // debug!("initial ir:\n{}", initial_ir.display_graphviz(true));
        let output_planned_ir =
            initial_ir.apply_local_pass_sequential(&self.verifier_config().planning_pass());
        // debug!(
        //     "output planned ir:\n{}",
        //     output_planned_ir.display_graphviz(true)
        // );
        let gadget_planned_ir = self.gadget_planned_ir_for_query(query, proof);
        // debug!(
        //     "gadget planned ir:\n{}",
        //     gadget_planned_ir.display_graphviz(true)
        // );

        let mut arg_verifier = self.arg_verifier().fork();
        arg_verifier.set_proof_ref(snark_proof);

        let verifier_tracking_pass = self.verifier_config().tracking_pass(
            arg_verifier.clone(),
            self.shared_config().ctx_oracles().clone(),
        );
        let mut tracked_ir = gadget_planned_ir.apply_local_pass_sequential(&verifier_tracking_pass);
        let output_memtable = if output_memtable.is_some()
            || tracked_ir.tree().root().name() != "ResultCheck"
        {
            output_memtable
        } else {
            Some(self.extract_output_memtable(query).await?)
        };
        self.track_query_output(&mut tracked_ir, output_memtable, arg_verifier.clone())
            .await?;
        let verifier_virtualization_pass = VerifierVirtualizationPass::<B>::new(&tracked_ir);
        let virtualized_ir = tracked_ir.apply_local_pass_sequential(&verifier_virtualization_pass);
        // debug!("tracked ir:\n{}", tracked_ir.display_graphviz(true));
        // debug!("virtualized ir:\n{}", virtualized_ir.display_graphviz(true));
        let gadget_ir_view = VerifierVirtualizedIr::new(
            virtualized_ir.tree().clone(),
            virtualized_ir.payloads().clone(),
        );
        let gadget_initialization_pass =
            VerifierGadgetInitializationPass::<B>::new(gadget_ir_view, arg_verifier.clone());
        let gadget_ready_ir =
            virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);
        // debug!(
        //     "gadget ready ir:\n{}",
        //     gadget_ready_ir.display_graphviz(true)
        // );

        let verify_ir_view = VerifierGadgetReadyIr::new(
            gadget_ready_ir.tree().clone(),
            gadget_ready_ir.payloads().clone(),
        );
        let verify_pass = VerifyPass::<B>::new(arg_verifier.clone(), verify_ir_view);
        let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&verify_pass);
        verify_pass.take_result()?;

        Ok((
            VerifierIrStages {
                initial: initial_ir,
                output_planned: output_planned_ir,
                gadget_planned: gadget_planned_ir,
                tracked: tracked_ir,
                virtualized: virtualized_ir,
                gadget_ready: gadget_ready_ir,
            },
            arg_verifier,
        ))
    }

    async fn track_query_output(
        &self,
        tracked_ir: &mut VerifierTrackedIr<B>,
        output_memtable: Option<Arc<MemTable>>,
        arg_verifier: ArgVerifier<B>,
    ) -> TTResult<()> {
        let root = tracked_ir.tree().root();
        if root.name() != "ResultCheck" {
            return Ok(());
        }

        let output_memtable = output_memtable.ok_or_else(|| {
            DataFusionError::Internal(
                "ResultCheck verification requires the compact query output".to_string(),
            )
        })?;
        let input_table = Self::result_check_input_table(tracked_ir)?;
        let target_num_rows = 1usize << input_table.log_size();
        let target_schema = input_table.schema().ok_or_else(|| {
            DataFusionError::Internal("ResultCheck input table schema is missing".to_string())
        })?;
        let src_positions = Self::result_check_src_positions(root.id(), &arg_verifier, target_num_rows)?;
        let materialized = Self::materialized_result_table_from_output(
            output_memtable,
            &target_schema,
            target_num_rows,
            &src_positions,
        )
        .await?;
        let arith_table = arithmetize_materialized_table::<B::F>(&materialized);
        let tracked_table = Self::track_output_table_oracle(&arith_table, &arg_verifier);
        tracked_ir.set_payload_for_node(
            root.id(),
            Some(PayloadStructure::PlanPayload(tracked_table)),
        );
        Ok(())
    }

    async fn extract_output_memtable(&self, query: &str) -> TTResult<Arc<MemTable>> {
        let df = self.shared_config().session_ctx().sql(query).await?;
        let base_schema = df.schema().as_arrow().clone();
        let batches = df.collect().await?;
        let (output_schema, output_batches) =
            Self::append_activator_and_pad_batches(&base_schema, batches)?;
        let mem_table = MemTable::try_new(Arc::new(output_schema), vec![output_batches])?;
        Ok(Arc::new(mem_table))
    }

    async fn materialized_table_from_memtable(
        mem_table: Arc<MemTable>,
        target_num_rows: Option<usize>,
    ) -> TTResult<MaterializedTable> {
        let ctx = SessionContext::new();
        let df = ctx.read_table(mem_table.clone())?;
        let mut batches = df.collect().await?;
        let schema = mem_table.schema();
        batches = Self::pad_memtable_batches_to_num_rows(schema.as_ref(), batches, target_num_rows)?;
        let row_count = batches.iter().map(|batch| batch.num_rows()).sum();
        let rebuilt = MemTable::try_new(mem_table.schema(), vec![batches.clone()])
            .expect("memtable rebuild from collected batches should succeed");
        Ok(MaterializedTable::new_with_batches(rebuilt, row_count, batches))
    }

    fn result_check_input_table(
        tracked_ir: &VerifierTrackedIr<B>,
    ) -> TTResult<TrackedTableOracle<B>> {
        let root = tracked_ir.tree().root();
        let input_id = root
            .children()
            .first()
            .map(|node| node.id())
            .ok_or_else(|| DataFusionError::Internal("ResultCheck input not found".to_string()))?;
        let input_table = tracked_ir
            .payload_for_node(&input_id)
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(table.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                DataFusionError::Internal("ResultCheck input payload not found".to_string())
            })?;
        Ok(input_table)
    }

    fn pad_memtable_batches_to_num_rows(
        schema: &Schema,
        batches: Vec<RecordBatch>,
        target_num_rows: Option<usize>,
    ) -> TTResult<Vec<RecordBatch>> {
        let row_count: usize = batches.iter().map(|batch| batch.num_rows()).sum();
        let Some(target_num_rows) = target_num_rows else {
            return Ok(batches);
        };
        if row_count > target_num_rows {
            return Err(DataFusionError::Internal(format!(
                "cannot pad output memtable from {} rows down to {} rows",
                row_count, target_num_rows
            ))
            .into());
        }
        if row_count == target_num_rows {
            return Ok(batches);
        }

        let schema_ref = Arc::new(schema.clone());
        let combined = if row_count == 0 || schema.fields().is_empty() {
            None
        } else {
            let batch_refs: Vec<&RecordBatch> = batches.iter().collect();
            Some(
                concat_batches(&schema_ref, batch_refs)
                    .map_err(|e| DataFusionError::Execution(e.to_string()))?,
            )
        };

        let pad = target_num_rows - row_count;
        let mut output_arrays = Vec::with_capacity(schema.fields().len());
        for (idx, field) in schema.fields().iter().enumerate() {
            let base = combined
                .as_ref()
                .map(|batch| batch.column(idx).clone())
                .unwrap_or_else(|| {
                    Self::inactive_padding_scalar(field.data_type())
                        .expect("padding scalar for schema field")
                        .to_array_of_size(0)
                        .expect("empty array for schema field")
                });
            let pad_arr = if field.name() == arithmetic::ACTIVATOR_COL_NAME {
                Arc::new(BooleanArray::from(vec![false; pad])) as ArrayRef
            } else {
                Self::inactive_padding_scalar(field.data_type())?.to_array_of_size(pad)?
            };
            output_arrays.push(
                concat(&[base.as_ref(), pad_arr.as_ref()])
                    .map_err(|e| DataFusionError::Execution(e.to_string()))?,
            );
        }

        let padded_batch = RecordBatch::try_new(schema_ref, output_arrays)
            .map_err(|e| DataFusionError::Execution(e.to_string()))?;
        Ok(vec![padded_batch])
    }

    fn inactive_padding_scalar(data_type: &DataType) -> TTResult<ScalarValue> {
        match ScalarValue::new_zero(data_type) {
            Ok(value) => Ok(value),
            Err(_) => match data_type {
                DataType::Utf8View => Ok(ScalarValue::Utf8View(Some(String::new()))),
                DataType::BinaryView => Ok(ScalarValue::BinaryView(Some(Vec::new()))),
                DataType::FixedSizeBinary(size) => {
                    Ok(ScalarValue::FixedSizeBinary(*size, Some(vec![0; *size as usize])))
                }
                _ => Err(DataFusionError::NotImplemented(format!(
                    "Can't create an inactive padding scalar from data_type \"{data_type}\""
                ))
                .into()),
            },
        }
    }

    fn append_activator_and_pad_batches(
        base_schema: &Schema,
        batches: Vec<RecordBatch>,
    ) -> TTResult<(Schema, Vec<RecordBatch>)> {
        let row_count: usize = batches.iter().map(|batch| batch.num_rows()).sum();
        let target = if row_count == 0 {
            2
        } else {
            row_count.next_power_of_two()
        };
        let output_schema = Self::schema_with_activator(base_schema);
        let output_schema_ref = Arc::new(output_schema.clone());
        let base_schema_ref = Arc::new(base_schema.clone());

        let combined = if row_count == 0 || base_schema.fields().is_empty() {
            None
        } else {
            let batch_refs: Vec<&RecordBatch> = batches.iter().collect();
            Some(
                concat_batches(&base_schema_ref, batch_refs)
                    .map_err(|e| DataFusionError::Execution(e.to_string()))?,
            )
        };

        let mut output_arrays = Vec::with_capacity(output_schema_ref.fields().len());
        for (idx, field) in base_schema.fields().iter().enumerate() {
            let array = if let Some(batch) = combined.as_ref() {
                let base = batch.column(idx).clone();
                let pad = target - row_count;
                if pad == 0 {
                    base
                } else {
                    let pad_arr =
                        Self::inactive_padding_scalar(field.data_type())?.to_array_of_size(pad)?;
                    concat(&[base.as_ref(), pad_arr.as_ref()])
                        .map_err(|e| DataFusionError::Execution(e.to_string()))?
                }
            } else {
                Self::inactive_padding_scalar(field.data_type())?.to_array_of_size(target)?
            };
            output_arrays.push(array);
        }

        let activator_values = std::iter::repeat_n(true, row_count)
            .chain(std::iter::repeat_n(false, target - row_count))
            .collect::<Vec<_>>();
        output_arrays.push(Arc::new(BooleanArray::from(activator_values)) as ArrayRef);

        let output_batch = RecordBatch::try_new(output_schema_ref, output_arrays)
            .map_err(|e| DataFusionError::Execution(e.to_string()))?;
        Ok((output_schema, vec![output_batch]))
    }

    fn schema_with_activator(base_schema: &Schema) -> Schema {
        let mut fields = base_schema
            .fields()
            .iter()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        fields.push(datafusion::arrow::datatypes::Field::new(
            arithmetic::ACTIVATOR_COL_NAME,
            DataType::Boolean,
            false,
        ));
        Schema::new_with_metadata(fields, base_schema.metadata().clone())
    }

    fn track_output_table_oracle(
        arith_table: &ArithTable<B::F>,
        arg_verifier: &ArgVerifier<B>,
    ) -> TrackedTableOracle<B> {
        let tracked_oracles = arith_table
            .polynomials()
            .iter()
            .map(|(field_ref, mle)| {
                let poly_evals = mle.evaluations();
                let num_vars = mle.num_vars();
                let oracle = Oracle::new_multivariate(arith_table.log_size(), move |point| {
                    Ok(eval_mle_at_point(&poly_evals, num_vars, &point))
                });
                (field_ref.clone(), arg_verifier.track_oracle(oracle))
            })
            .collect();
        TrackedTableOracle::new(
            arith_table.schema(),
            tracked_oracles,
            arith_table.log_size(),
        )
    }

    fn count_active_rows(batch: &RecordBatch) -> usize {
        batch
            .schema()
            .column_with_name(arithmetic::ACTIVATOR_COL_NAME)
            .and_then(|(idx, _)| batch.column(idx).as_any().downcast_ref::<BooleanArray>())
            .map(|activator| (0..activator.len()).filter(|&idx| activator.value(idx)).count())
            .unwrap_or_else(|| batch.num_rows())
    }

    fn scatter_compact_output_to_support(
        schema: &Schema,
        compact_batch: Option<&RecordBatch>,
        target_num_rows: usize,
        support_positions: &[usize],
    ) -> TTResult<RecordBatch> {
        let schema_ref = Arc::new(schema.clone());
        let mut output_arrays = Vec::with_capacity(schema.fields().len());

        for (col_idx, field) in schema.fields().iter().enumerate() {
            if field.name() == arithmetic::ACTIVATOR_COL_NAME {
                let mut activator = vec![false; target_num_rows];
                for &position in support_positions {
                    activator[position] = true;
                }
                output_arrays.push(Arc::new(BooleanArray::from(activator)) as ArrayRef);
                continue;
            }

            let inactive = Self::inactive_padding_scalar(field.data_type())?;
            let mut values = vec![inactive; target_num_rows];
            if let Some(batch) = compact_batch {
                let (source_idx, _) = batch
                    .schema()
                    .column_with_name(field.name())
                    .ok_or_else(|| {
                        DataFusionError::Internal(format!(
                            "ResultCheck output column {} not found",
                            field.name()
                        ))
                    })?;
                for (row_idx, &position) in support_positions.iter().enumerate() {
                    values[position] = ScalarValue::try_from_array(
                        batch.column(source_idx).as_ref(),
                        row_idx,
                    )?
                    .cast_to(field.data_type())?;
                }
            }
            output_arrays.push(ScalarValue::iter_to_array(values)?);
        }

        RecordBatch::try_new(schema_ref, output_arrays)
            .map_err(|e| DataFusionError::Execution(e.to_string()).into())
    }

    fn active_support_positions(evals: Vec<B::F>) -> Vec<usize> {
        evals.into_iter()
            .enumerate()
            .filter_map(|(idx, value)| (!value.is_zero()).then_some(idx))
            .collect()
    }

    fn result_check_src_positions(
        id: tt_core::irs::nodes::NodeId,
        arg_verifier: &ArgVerifier<B>,
        target_num_rows: usize,
    ) -> TTResult<Vec<usize>> {
        let src_poly_id_field = arg_verifier.miscellaneous_field_element(&Self::result_check_src_poly_key(id))?;
        let src_poly_id = TrackerID::from_usize(src_poly_id_field.into_bigint().as_ref()[0] as usize);
        let src_poly = arg_verifier.sent_mv_poly_by_id(src_poly_id)?;
        let evals = src_poly.evaluations();
        if evals.len() != target_num_rows {
            return Err(DataFusionError::Internal(format!(
                "ResultCheck source polynomial has {} rows but expected {target_num_rows}",
                evals.len()
            ))
            .into());
        }
        Ok(Self::active_support_positions(evals))
    }

    fn result_check_src_poly_key(id: tt_core::irs::nodes::NodeId) -> String {
        format!("{RESULT_CHECK_SRC_POLY_ID_PREFIX}_{id}")
    }

    async fn materialized_result_table_from_output(
        output_memtable: Arc<MemTable>,
        target_schema: &Schema,
        target_num_rows: usize,
        support_positions: &[usize],
    ) -> TTResult<MaterializedTable> {
        let ctx = SessionContext::new();
        let df = ctx.read_table(output_memtable.clone())?;
        let compact_batches = df.collect().await?;
        let compact_schema = output_memtable.schema();
        let compact_row_count = compact_batches.iter().map(|batch| batch.num_rows()).sum::<usize>();

        let compact = if compact_row_count == 0 {
            None
        } else {
            let batch_refs: Vec<&RecordBatch> = compact_batches.iter().collect();
            Some(
                concat_batches(&compact_schema, batch_refs)
                    .map_err(|e| DataFusionError::Execution(e.to_string()))?,
            )
        };

        let compact_active_rows = compact
            .as_ref()
            .map_or(0, |batch| Self::count_active_rows(batch));
        if compact_active_rows != support_positions.len() {
            return Err(DataFusionError::Internal(format!(
                "ResultCheck output has {compact_active_rows} active rows but source support has {}",
                support_positions.len()
            ))
            .into());
        }

        let sparse_batch = Self::scatter_compact_output_to_support(
            target_schema,
            compact.as_ref(),
            target_num_rows,
            support_positions,
        )?;
        let rebuilt = MemTable::try_new(Arc::new(target_schema.clone()), vec![vec![sparse_batch.clone()]])?;
        Ok(MaterializedTable::new_with_batches(
            rebuilt,
            target_num_rows,
            vec![sparse_batch],
        ))
    }
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

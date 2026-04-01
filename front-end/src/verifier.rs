use arithmetic::table::ArithTable;
use ark_ff::Field;
use ark_piop::{verifier::ArgVerifier, verifier::structs::oracle::Oracle, SnarkBackend};
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
use indexmap::IndexMap;
use std::sync::Arc;
use tracing::debug;
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

use crate::{shared::TTSharedConfig, structs::TTProof};

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

        // Step 1: Parse and prepare the initial IR from the proof
        let snark_proof = proof.as_inner();
        let mut arg_verifier = self.arg_verifier().fork();
        arg_verifier.set_proof_ref(snark_proof);

        // Step 2: Apply the tracking pass
        let verifier_tracking_pass = self.verifier_config().tracking_pass(
            arg_verifier.clone(),
            self.shared_config().ctx_oracles().clone(),
        );
        let mut tracked_ir = gadget_planned_ir.apply_local_pass_sequential(&verifier_tracking_pass);
        self.track_query_output(&mut tracked_ir, output_memtable, arg_verifier.clone())
            .await?;

        // Step 3: Apply the virtualization pass
        let verifier_virtualization_pass = VerifierVirtualizationPass::<B>::new(&tracked_ir);
        let virtualized_ir = tracked_ir.apply_local_pass_sequential(&verifier_virtualization_pass);

        let gadget_ir_view = VerifierVirtualizedIr::new(
            virtualized_ir.tree().clone(),
            virtualized_ir.payloads().clone(),
        );

        // Step 4: Apply the gadget initialization pass
        let gadget_initialization_pass =
            VerifierGadgetInitializationPass::<B>::new(gadget_ir_view, arg_verifier.clone());
        let gadget_ready_ir =
            virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);

        let verify_ir_view = VerifierGadgetReadyIr::new(
            gadget_ready_ir.tree().clone(),
            gadget_ready_ir.payloads().clone(),
        );

        // Step 5: Apply the verification pass
        let verify_pass = VerifyPass::<B>::new(arg_verifier.clone(), verify_ir_view);
        let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&verify_pass);

        // Step 6: Verify the SNARK verification
        verify_pass.take_result()?;
        arg_verifier.verify()?;
        Ok(())
    }

    pub async fn verify(&self, query: &str, proof: &TTProof<B>) -> TTResult<()> {
        let output_memtable = self.extract_output_memtable(query).await?;
        let gadget_planned_ir = self.gadget_planned_ir_for_query(query, proof);
        self.verify_with_gadget_planned_ir(proof, &gadget_planned_ir, Some(output_memtable))
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

    pub async fn verify_with_preprocessed_query(
        &self,
        query: &str,
        proof: &TTProof<B>,
        gadget_planned_ir: &GadgetPlannedIr<B>,
    ) -> TTResult<()> {
        let output_memtable = self.extract_output_memtable(query).await?;
        self.verify_with_gadget_planned_ir(proof, gadget_planned_ir, Some(output_memtable))
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
        let output_memtable = self.extract_output_memtable(query).await?;
        self.build_ir_stages_with_output(query, proof, Some(output_memtable))
            .await
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
        let materialized = Self::materialized_table_from_memtable(output_memtable, None).await?;
        let arith_table = arithmetize_materialized_table::<B::F>(&materialized);
        let tracked_table = Self::track_output_table_oracle(&arith_table, &arg_verifier);
        let gadget_id = root
            .children()
            .into_iter()
            .find(|child| child.name() == "ResultCheck")
            .map(|child| child.id())
            .ok_or_else(|| {
                DataFusionError::Internal(
                    "ResultCheck root missing gadget child".to_string(),
                )
            })?;
        let mut gadget_payload = match tracked_ir.payload_for_node(&gadget_id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(
            tt_core::irs::nodes::gadget::utils::result_check::OUTPUT_LABEL.to_string(),
            tracked_table,
        );
        tracked_ir.set_payload_for_node(
            gadget_id,
            Some(PayloadStructure::GadgetPayload(gadget_payload)),
        );
        Ok(())
    }

    async fn extract_output_memtable(&self, query: &str) -> TTResult<Arc<MemTable>> {
        let lp = self.shared_config().query_to_lp(query).await;
        let optimized_lp = self.shared_config().analyze_and_optimize_lp(lp).await;
        let df = datafusion::dataframe::DataFrame::new(
            self.shared_config().session_ctx().state(),
            optimized_lp,
        );
        let logical_schema = df.schema().as_arrow().clone();
        let batches = df.collect().await?;
        let base_schema = batches
            .first()
            .map(|batch| batch.schema().as_ref().clone())
            .unwrap_or_else(|| logical_schema.clone());
        if query.contains("avg(") {
            let batch_schema = batches.first().map(|batch| batch.schema());
            debug!(
                "extract_output_memtable verifier: logical_schema={:?}, first_batch_schema={:?}",
                logical_schema,
                batch_schema
            );
        }
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
        let has_activator = base_schema
            .fields()
            .iter()
            .any(|field| field.name() == arithmetic::ACTIVATOR_COL_NAME);
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

        if !has_activator {
            let activator_values = std::iter::repeat_n(true, row_count)
                .chain(std::iter::repeat_n(false, target - row_count))
                .collect::<Vec<_>>();
            output_arrays.push(Arc::new(BooleanArray::from(activator_values)) as ArrayRef);
        }

        let output_batch = RecordBatch::try_new(output_schema_ref, output_arrays)
            .map_err(|e| DataFusionError::Execution(e.to_string()))?;
        Ok((output_schema, vec![output_batch]))
    }

    fn schema_with_activator(base_schema: &Schema) -> Schema {
        if base_schema
            .fields()
            .iter()
            .any(|field| field.name() == arithmetic::ACTIVATOR_COL_NAME)
        {
            return base_schema.clone();
        }
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
                let tracked_oracle = arg_verifier.track_oracle(oracle);
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

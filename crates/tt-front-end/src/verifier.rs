use ark_piop::{SnarkBackend, verifier::ArgVerifier};
use datafusion::{
    arrow::datatypes::Schema,
    datasource::{MemTable, TableProvider},
    prelude::SessionContext,
};
use datafusion_common::DataFusionError;
use datafusion_expr::LogicalPlan;
use proof_planner::data_dependent_lp_optimizer::{OptimizationHints, apply_optimization_hints};
use std::{collections::HashSet, sync::Arc};
use tracing::debug;
use tt_core::{
    ctx_oracles::CtxOracles,
    errors::{TTError, TTResult},
    irs::{
        nodes::plan::result_check,
        shared_ir::{EmptyIr, GadgetPlannedIr, OutputPlannedIr},
    },
    verifier::{
        irs::{GadgetReadyIr as VerifierGadgetReadyIr, VirtualizedIr as VerifierVirtualizedIr},
        passes::{
            gadget_initialization::GadgetInitializationPass as VerifierGadgetInitializationPass,
            gadget_planning::GadgetPlanningPass as VerifierGadgetPlanningPass,
            output_planning::OutputPlanningPass as VerifierOutputPlanningPass,
            tracking::TrackingPass as VerifierTrackingPass, verify::VerifyPass,
            virtualization::VirtualizationPass as VerifierVirtualizationPass,
        },
    },
};

use crate::{shared::TTSharedConfig, structs::TTProof};

// Truth Table verifier configuration
pub struct TTVerifierConfig<B: SnarkBackend> {
    phantom: std::marker::PhantomData<B>,
}

impl<B: SnarkBackend> TTVerifierConfig<B> {
    /// Create the default verifier-side pass factory.
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }

    /// Build the verifier output-planning pass.
    pub fn planning_pass(&self) -> VerifierOutputPlanningPass<B> {
        VerifierOutputPlanningPass::new()
    }

    /// Build the verifier gadget-planning pass for a planned IR.
    pub fn gadget_planning_pass(
        &self,
        planned_ir: &OutputPlannedIr<B>,
    ) -> VerifierGadgetPlanningPass<B> {
        VerifierGadgetPlanningPass::new(planned_ir)
    }

    /// Build the verifier tracking pass using the verifier state, context oracles,
    /// optional query result table, and the set of columns whose char-level
    /// side commitments the prover emits (from `Tree::required_side_columns`).
    fn tracking_pass(
        &self,
        arg_verifier: ArgVerifier<B>,
        ctx_oracles: CtxOracles<B>,
        output_memtable: Option<Arc<MemTable>>,
        side_columns: std::collections::BTreeSet<String>,
    ) -> VerifierTrackingPass<B> {
        VerifierTrackingPass::new(arg_verifier, ctx_oracles, output_memtable, side_columns)
    }
}

/// Opaque verifier state coupling a validated public result to its proof plan.
///
/// Construction is intentionally restricted to
/// [`TTVerifier::prepare_verification`]. This prevents low-level verification
/// callers from bypassing the visible SQL schema check, supplying NULL values
/// whose validity bits are not yet authenticated, normalizing twice, or
/// supplying a logical plan that was not derived from the public query and the
/// optimization hints carried by the proof.
///
/// This state currently binds the public result to the query's field encodings.
/// It is a full SQL-value binding only for NULL-free query pipelines: public
/// NULLs are rejected here, but validity bits of internal nullable columns are
/// not yet authenticated by the proof system.
pub struct PreparedVerification<B: SnarkBackend> {
    raw_result: Arc<MemTable>,
    gadget_planned_ir: Arc<GadgetPlannedIr<B>>,
    optimization_hints: OptimizationHints,
}

impl<B: SnarkBackend> Clone for PreparedVerification<B> {
    fn clone(&self) -> Self {
        Self {
            raw_result: self.raw_result.clone(),
            gadget_planned_ir: self.gadget_planned_ir.clone(),
            optimization_hints: self.optimization_hints.clone(),
        }
    }
}

impl<B: SnarkBackend> Default for TTVerifierConfig<B> {
    fn default() -> Self {
        Self::new()
    }
}

/// Truth Table Verifier
pub struct TTVerifier<B: SnarkBackend> {
    /// The configuration specific to the verifier
    verifier_config: TTVerifierConfig<B>,
    /// The configuration shared between prover and verifier
    shared_config: TTSharedConfig<B>,
    /// The inner argument verifier
    arg_verifier: ArgVerifier<B>,
}

impl<B: SnarkBackend> TTVerifier<B> {
    /// Create a verifier from its pass configuration, shared configuration, and
    /// inner SNARK verifier.
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

    /// Borrow the verifier-specific configuration.
    fn verifier_config(&self) -> &TTVerifierConfig<B> {
        &self.verifier_config
    }

    /// Borrow the configuration shared between the prover and verifier.
    fn shared_config(&self) -> &TTSharedConfig<B> {
        &self.shared_config
    }

    /// Borrow the inner SNARK verifier state.
    fn arg_verifier(&self) -> &ArgVerifier<B> {
        &self.arg_verifier
    }

    /// Verify a proof using the public result and exact gadget-planned IR coupled
    /// by [`TTVerifier::prepare_verification`].
    ///
    /// The present ResultCheck relation authenticates field encodings and
    /// assumes the internal query pipeline is NULL-free. Authenticated Arrow
    /// validity columns are required before this can be advertised as general
    /// SQL NULL-aware result equality.
    pub async fn verify_prepared(
        &self,
        proof: &TTProof<B>,
        prepared: PreparedVerification<B>,
    ) -> TTResult<()> {
        if &prepared.optimization_hints != proof.optimization_hints() {
            return Err(TTError::DataFusion(DataFusionError::Plan(
                "prepared verification state was built for different optimization hints"
                    .to_string(),
            )));
        }
        let PreparedVerification {
            raw_result,
            gadget_planned_ir,
            optimization_hints: _,
        } = prepared;
        // Step 1: Parse and prepare the initial IR from the proof
        let snark_proof = proof.as_snark_proof();
        let mut arg_verifier = self.arg_verifier().fork();
        arg_verifier.set_proof_ref(snark_proof);

        // Step 2: Apply the tracking pass. The side-column set is derived
        // from the same IR tree the prover used, so both sides expect the
        // same per-column side commitments without a wire hint.
        let side_columns = gadget_planned_ir.tree().required_side_columns();
        let verifier_tracking_pass = self.verifier_config().tracking_pass(
            arg_verifier.clone(),
            self.shared_config().ctx_oracles().clone(),
            Some(raw_result),
            side_columns,
        );
        let mut tracked_ir = gadget_planned_ir.apply_local_pass_sequential(&verifier_tracking_pass);
        verifier_tracking_pass.finish(&mut tracked_ir).await?;

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
        verify_pass.take_result().map_err(|err| {
            TTError::DataFusion(DataFusionError::Internal(format!(
                "verifier verify_pass failed before cryptographic verification: {err:?}"
            )))
        })?;
        arg_verifier.verify().map_err(|err| {
            TTError::DataFusion(DataFusionError::Internal(format!(
                "verifier cryptographic verification failed: {err:?}"
            )))
        })?;
        Ok(())
    }

    /// Verify a proof end-to-end by replaying the verifier LP and IR pipelines and
    /// normalizing the verifier-supplied public result exactly once.
    ///
    /// Public NULLs fail closed. Callers must additionally restrict queries and
    /// committed inputs to a NULL-free pipeline until internal validity bits are
    /// authenticated.
    pub async fn verify(
        &self,
        query: &str,
        proof: &TTProof<B>,
        result: Arc<MemTable>,
    ) -> TTResult<()> {
        let prepared = self.prepare_verification(query, proof, result).await?;
        self.verify_prepared(proof, prepared).await
    }

    /// Prepare all public verifier state for a query, proof, and raw result.
    ///
    /// The logical plan is always reconstructed here from the public query and
    /// the optimization hints carried by `proof`; callers cannot substitute an
    /// independently chosen plan. The resulting opaque object couples that plan
    /// to the validated raw public result for cached verification; the low-level
    /// tracking pass performs the single normalization step.
    pub async fn prepare_verification(
        &self,
        query: &str,
        proof: &TTProof<B>,
        result: Arc<MemTable>,
    ) -> TTResult<PreparedVerification<B>> {
        let lp = self.lp_passes(query, proof).await?;
        self.prepare_public_result(lp, proof.optimization_hints().clone(), result)
            .await
    }

    /// Validate a raw public result for a verifier-derived plan.
    ///
    /// The exact visible field sequence (name, Arrow type, and nullability) must
    /// match the plan. NULL cells are rejected until the arithmetic encoding
    /// authenticates validity columns. The raw table is retained: verifier
    /// TrackingPass owns the single activation/padding normalization step, even
    /// for low-level callers. The gadget-planned IR is built from this same plan
    /// and stored inside the opaque return value, so a caller cannot cross-wire
    /// a result prepared for one schema with another IR.
    async fn prepare_public_result(
        &self,
        lp: LogicalPlan,
        optimization_hints: OptimizationHints,
        result: Arc<MemTable>,
    ) -> TTResult<PreparedVerification<B>> {
        validate_public_result_schema(lp.schema().as_arrow(), result.schema().as_ref())?;
        result_check::validate_public_result_encoding::<B::F>(result.schema().as_ref())?;
        let ctx = SessionContext::new();
        let df = ctx.read_table(result.clone())?;
        let batches = df.collect().await?;
        tt_core::prover::passes::materialization::reject_nulls_in_public_result(&batches)?;
        let gadget_planned_ir = Arc::new(self.ir_passes(lp).await?);
        Ok(PreparedVerification {
            raw_result: result,
            gadget_planned_ir,
            optimization_hints,
        })
    }

    /// Run the verifier logical-plan pipeline, including replaying the optimization
    /// hints embedded in the proof.
    async fn lp_passes(
        &self,
        query: &str,
        proof: &TTProof<B>,
    ) -> TTResult<datafusion_expr::LogicalPlan> {
        // 1. Build the raw logical plan from the SQL query.
        let initial_lp = self.shared_config().query_to_lp(query).await;
        debug!(
            "verifier initial logical plan:\n{}",
            initial_lp.display_graphviz()
        );

        // 2. Re-run analysis and structural optimization locally on the verifier.
        let analyzed_lp = self.shared_config().analyze_lp(initial_lp).await;
        let analyzed_and_optimized_lp = self.shared_config().optimize_lp(analyzed_lp).await;

        // 3. Replay the prover's data-dependent optimization choices from the proof.
        let analyzed_and_optimized_lp =
            apply_optimization_hints(analyzed_and_optimized_lp, proof.optimization_hints())
                .map_err(tt_core::errors::TTError::from)?;
        debug!(
            "verifier optimized and analyzed logical plan:\n{}",
            analyzed_and_optimized_lp.display_graphviz()
        );
        Ok(analyzed_and_optimized_lp)
    }

    /// Run the verifier IR pipeline up through gadget planning.
    async fn ir_passes(&self, lp: datafusion_expr::LogicalPlan) -> TTResult<GadgetPlannedIr<B>> {
        // 1. Convert the logical plan into the initial truth-table IR.
        let initial_ir = EmptyIr::<B>::from_logical_plan(&lp);
        debug!(
            "verifier initial ir:\n{}",
            initial_ir.display_graphviz(true)
        );

        // 2. Apply proof-plan optimizer rewrites before verifier-specific passes.
        let optimized_initial_ir = self.shared_config().pp_optimizer().optimize(initial_ir);
        debug!(
            "verifier optimized initial ir:\n{}",
            optimized_initial_ir.display_graphviz(true)
        );

        // 3. Run output planning and gadget planning to prepare the verifier IR.
        let output_planned_ir = optimized_initial_ir
            .apply_local_pass_sequential(&self.verifier_config().planning_pass());
        let gadget_planned_ir = output_planned_ir.apply_local_pass_sequential(
            &self
                .verifier_config()
                .gadget_planning_pass(&output_planned_ir),
        );
        debug!(
            "verifier gadget planned ir:\n{}",
            gadget_planned_ir.display_graphviz(true)
        );
        Ok(gadget_planned_ir)
    }
}

/// Require the public result file to have exactly the query's visible schema.
///
/// Arithmetized values do not uniquely determine SQL types: a small positive
/// signed integer and the same unsigned integer encode to the same field
/// element. Checking the schema before arithmetization also prevents a caller
/// from dropping a selected column and asking ResultCheck to prove only the
/// remaining projection.
fn validate_public_result_schema(expected: &Schema, actual: &Schema) -> TTResult<()> {
    if actual.fields().iter().any(|field| {
        field.name() == arithmetic::ACTIVATOR_COL_NAME
            || field.name() == arithmetic::ROW_ID_COL_NAME
    }) {
        return Err(TTError::DataFusion(DataFusionError::Plan(format!(
            "raw public result must not contain reserved internal columns {} or {}",
            arithmetic::ACTIVATOR_COL_NAME,
            arithmetic::ROW_ID_COL_NAME
        ))));
    }
    if expected.fields().len() != actual.fields().len() {
        return Err(TTError::DataFusion(DataFusionError::Plan(format!(
            "public result has {} columns, but the query produces {}",
            actual.fields().len(),
            expected.fields().len()
        ))));
    }
    let mut names = HashSet::new();
    if actual
        .fields()
        .iter()
        .any(|field| !names.insert(field.name()))
    {
        return Err(TTError::DataFusion(DataFusionError::Plan(
            "public result contains duplicate column names, which ResultCheck cannot align unambiguously"
                .to_string(),
        )));
    }
    for (expected_field, actual_field) in expected.fields().iter().zip(actual.fields()) {
        if expected_field.name() != actual_field.name()
            || expected_field.data_type() != actual_field.data_type()
            || expected_field.is_nullable() != actual_field.is_nullable()
        {
            return Err(TTError::DataFusion(DataFusionError::Plan(format!(
                "public result field {actual_field:?} does not match query field {expected_field:?}"
            ))));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_public_result_schema;
    use datafusion::arrow::datatypes::{DataType, Field, Schema};

    #[test]
    fn prepared_public_result_rejects_an_omitted_column() {
        let expected = Schema::new(vec![
            Field::new("left", DataType::Int64, false),
            Field::new("right", DataType::Int64, false),
        ]);
        let omitted = Schema::new(vec![Field::new("left", DataType::Int64, false)]);
        assert!(validate_public_result_schema(&expected, &omitted).is_err());
    }

    #[test]
    fn prepared_public_result_rejects_an_existing_activator() {
        let schema = Schema::new(vec![Field::new(
            arithmetic::ACTIVATOR_COL_NAME,
            DataType::Boolean,
            false,
        )]);
        assert!(validate_public_result_schema(&schema, &schema).is_err());
    }

    #[test]
    fn prepared_public_result_rejects_an_existing_row_id() {
        let schema = Schema::new(vec![Field::new(
            arithmetic::ROW_ID_COL_NAME,
            DataType::Int64,
            false,
        )]);
        assert!(validate_public_result_schema(&schema, &schema).is_err());
    }
}

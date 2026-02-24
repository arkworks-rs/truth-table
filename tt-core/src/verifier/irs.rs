//! Intermediate representations (IRs) for the verifier’s truth-table pipeline.
//!
//! This module defines type aliases for the various IRs the verifier's pipeline, ranging from simple plans for computing the witnesses to fully arithmetized and tracked polynomials ready for a SNARK verifier.

use crate::{
    irs::{ir::Ir, payloads::{HintDFPayload, VerifierHintDFPayload}},
    verifier::payloads::{GadgetReadyPayload, TrackedPayload, VirtualizedPayload},
};

/// The planned Intermediate Representation with verifier-side hint payloads.
pub type OutputPlannedIr<B> = Ir<B, VerifierHintDFPayload>;
/// The gadget-planned Intermediate Representation with verifier-side hint payloads.
pub type GadgetPlannedIr<B> = Ir<B, VerifierHintDFPayload>;
/// The tracked Intermediate Representation with tracked table payloads.
///
/// This IR represents the stage in the verifier's pipeline where the proof tree nodes contain tracked tables; i.e. tables that have commited polynomials and already appended to the verifier's transcript.
pub type TrackedIr<B> = Ir<B, TrackedPayload<B>>;
/// The virtualized Intermediate Representation with virtualized table payloads.
///
/// This IR represents the final stage in the verifier's pipeline where the virtual witnesses were added to the proof tree nodes.
pub type VirtualizedIr<B> = Ir<B, VirtualizedPayload<B>>;
/// The gadget-ready Intermediate Representation with gadget-initialized payloads.
///
/// This IR represents the stage after gadget initialization where gadget-specific payloads
/// have been prepared on top of the virtualized IR.
pub type GadgetReadyIr<B> = Ir<B, GadgetReadyPayload<B>>;

#[cfg(test)]
mod test {
    use super::*;
    use crate::ctx_oracles::CtxOracles;
    use crate::irs::shared_ir::EmptyIr;
    use crate::irs::{payloads::HintDFPayload, tree::Tree};
    use crate::prover::passes::{
        arithmetization::ArithmetizationPass, gadget_initialization::GadgetInitializationPass,
        materialization::MaterializationPass, output_planning::OutputPlanningPass,
        proving::ProvingPass,
        tracking::TrackingPass as ProverTrackingPass,
        virtualization::VirtualizationPass as ProverVirtualizationPass,
    };
    use crate::verifier::passes::{
        gadget_initialization::GadgetInitializationPass as VerifierGadgetInitializationPass,
        tracking::TrackingPass as VerifierTrackingPass, verify::VerifyPass,
        virtualization::VirtualizationPass as VerifierVirtualizationPass,
    };
    use arithmetic::ACTIVATOR_FIELD;
    use ark_piop::{
        DefaultSnarkBackend, SnarkBackend,
        pcs::{PCS, PolynomialCommitment},
        prover::ArgProver,
        prover::structs::proof::SNARKProof,
        structs::TrackerID,
        test_utils::test_prelude,
        verifier::ArgVerifier,
    };
    use datafusion::arrow::array::BooleanArray;
    use datafusion::{
        arrow::{
            array::{ArrayRef, Int32Array},
            datatypes::{DataType, Field, Schema},
            record_batch::RecordBatch,
        },
        prelude::SessionContext,
    };
    use std::sync::Arc;

    type Backend = DefaultSnarkBackend;
    type Commitment =
        <<Backend as SnarkBackend>::MvPCS as PCS<<Backend as SnarkBackend>::F>>::Commitment;

    fn dummy_schema() -> Arc<Schema> {
        Arc::new(Schema::new(vec![
            Field::new("first_column", DataType::Int32, false),
            Field::new("second_column", DataType::Int32, false),
            Field::new("third_column", DataType::Int32, false),
            ACTIVATOR_FIELD.as_ref().clone(),
        ]))
    }

    fn register_dummy_table(ctx: &SessionContext) {
        let schema = dummy_schema();
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![1, 2, 3, 4])) as ArrayRef,
                Arc::new(Int32Array::from(vec![10, 20, 30, 40])) as ArrayRef,
                Arc::new(Int32Array::from(vec![100, 200, 300, 400])) as ArrayRef,
                Arc::new(BooleanArray::from(vec![true, true, false, true])) as ArrayRef,
            ],
        )
        .unwrap();
        ctx.register_batch("dummy_table", batch).unwrap();
    }

    fn queries() -> Vec<&'static str> {
        vec![
            "SELECT first_column, second_column FROM dummy_table ",
            "SELECT first_column, second_column FROM dummy_table where third_column = 150",
        ]
    }

    #[allow(unused)]
    fn verifier_with_dummy_proof(num_commitments: usize) -> ArgVerifier<Backend> {
        let (_, mut verifier) = test_prelude::<Backend>().unwrap();
        let mut proof = SNARKProof::<Backend>::default();
        for id in 0..num_commitments {
            let mut commitment = Commitment::default();
            commitment.set_log_size(1);
            proof
                .mv_pcs_subproof
                .comitments
                .insert(TrackerID::from_usize(id), commitment);
        }
        verifier.set_proof(proof);
        verifier
    }

    #[allow(unused)]
    fn count_materialized_columns(ir: &Ir<Backend, HintDFPayload>) -> usize {
        ir.payloads()
            .values()
            .filter_map(|payload| payload.as_ref())
            .map(|payload| match payload {
                HintDFPayload::PlanPayload(hint_df) => hint_df
                    .field_materialization_iter()
                    .filter(|(_, mat)| **mat)
                    .count(),
                HintDFPayload::GadgetPayload(map) => map
                    .values()
                    .map(|hint_df| {
                        hint_df
                            .field_materialization_iter()
                            .filter(|(_, mat)| **mat)
                            .count()
                    })
                    .sum::<usize>(),
            })
            .sum()
    }

    async fn perform_prover_passes(
        query: &str,
        arg_prover: &mut ArgProver<Backend>,
    ) -> SNARKProof<Backend> {
        ////////////////////////////////////////////////////////////////////////
        // Prover stuff
        ////////////////////////////////////////////////////////////////////////
        let ctx = SessionContext::new();
        register_dummy_table(&ctx);

        let planning_pass = OutputPlanningPass::<Backend>::new();
        let materialization_pass = MaterializationPass::<Backend>::new();
        let arithmetization_pass = ArithmetizationPass::<Backend>::new();
        let commitment_pass = crate::prover::passes::commitment::CommitmentPass::<Backend>::new(
            arg_prover.mv_pcs_prover_param(),
            CtxOracles::default(),
        );

        let df = ctx.sql(query).await.unwrap();
        let lp = df.into_unoptimized_plan();
        let tree = Tree::from_logical_plan(&lp);
        let initial_ir = EmptyIr::<Backend>::new_empty(tree);

        let planned_ir = initial_ir.apply_local_pass_parallel(&planning_pass);
        let materialized_ir = planned_ir.apply_local_pass_parallel(&materialization_pass);
        let arithmetized_ir = materialized_ir.apply_local_pass_parallel(&arithmetization_pass);
        let committed_ir = arithmetized_ir.apply_local_pass_parallel(&commitment_pass);
        let prover_tracking_pass = ProverTrackingPass::<Backend>::new(
            arg_prover.clone(),
            arithmetized_ir.payloads().clone(),
        );
        let tracked_ir_prover = committed_ir.apply_local_pass_sequential(&prover_tracking_pass);
        let prover_virtualization_pass =
            ProverVirtualizationPass::<Backend>::new(&tracked_ir_prover);
        let virtualized_ir =
            tracked_ir_prover.apply_local_pass_sequential(&prover_virtualization_pass);
        let gadget_ir_view = crate::prover::irs::VirtualizedIr::new(
            virtualized_ir.tree().clone(),
            virtualized_ir.payloads().clone(),
        );
        let gadget_initialization_pass =
            GadgetInitializationPass::<Backend>::new(gadget_ir_view, arg_prover.clone());
        let gadget_ready_ir =
            virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);
        let proving_ir_view = crate::prover::irs::GadgetReadyIr::new(
            gadget_ready_ir.tree().clone(),
            gadget_ready_ir.payloads().clone(),
        );
        let proving_pass = ProvingPass::<Backend>::new(arg_prover.clone(), proving_ir_view);
        let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&proving_pass);

        arg_prover.build_proof().expect("prover should build proof")
    }

    #[tokio::test]
    async fn builds_tracked_ir_from_logical_plan() {
        for query in queries() {
            // Create a prover and a verifier
            let (mut arg_prover, mut arg_verifier) = test_prelude::<Backend>().unwrap();
            let proof = perform_prover_passes(query, &mut arg_prover).await;
            arg_verifier.set_proof(proof);

            let ctx = SessionContext::new();
            register_dummy_table(&ctx);

            let planning_pass = OutputPlanningPass::<Backend>::new();

            let df = ctx.sql(query).await.unwrap();
            let lp = df.into_unoptimized_plan();
            let tree = Tree::from_logical_plan(&lp);
            let initial_ir = EmptyIr::<Backend>::new_empty(tree);

            let planned_ir = initial_ir.apply_local_pass_parallel(&planning_pass);

            let verifier_tracking_pass =
                VerifierTrackingPass::<Backend>::new(arg_verifier, CtxOracles::default());
            let tracked_ir = planned_ir.apply_local_pass_sequential(&verifier_tracking_pass);
            println!("Planned Query: {query}");
            println!("{}", tracked_ir.display_graphviz(true));
        }
    }

    #[tokio::test]
    async fn builds_virtualized_ir_from_logical_plan() {
        for query in queries() {
            // Create a prover and a verifier
            let (mut arg_prover, mut arg_verifier) = test_prelude::<Backend>().unwrap();
            let proof = perform_prover_passes(query, &mut arg_prover).await;
            arg_verifier.set_proof(proof);

            let ctx = SessionContext::new();
            register_dummy_table(&ctx);

            let planning_pass = OutputPlanningPass::<Backend>::new();

            let df = ctx.sql(query).await.unwrap();
            let lp = df.into_unoptimized_plan();
            let tree = Tree::from_logical_plan(&lp);
            let initial_ir = EmptyIr::<Backend>::new_empty(tree);

            let planned_ir = initial_ir.apply_local_pass_parallel(&planning_pass);

            let verifier_tracking_pass =
                VerifierTrackingPass::<Backend>::new(arg_verifier, CtxOracles::default());
            let tracked_ir = planned_ir.apply_local_pass_sequential(&verifier_tracking_pass);
            let verifier_virtualization_pass =
                VerifierVirtualizationPass::<Backend>::new(&tracked_ir);
            let _virtualized_ir =
                tracked_ir.apply_local_pass_sequential(&verifier_virtualization_pass);
            println!("Planned Query: {query}");
            println!("{}", tracked_ir.display_graphviz(true));
        }
    }

    #[tokio::test]
    async fn builds_gadget_initialized_ir_from_logical_plan() {
        for query in queries() {
            // Create a prover and a verifier
            let (mut arg_prover, mut arg_verifier) = test_prelude::<Backend>().unwrap();
            let proof = perform_prover_passes(query, &mut arg_prover).await;
            arg_verifier.set_proof(proof);

            let ctx = SessionContext::new();
            register_dummy_table(&ctx);

            let planning_pass = OutputPlanningPass::<Backend>::new();

            let df = ctx.sql(query).await.unwrap();
            let lp = df.into_unoptimized_plan();
            let tree = Tree::from_logical_plan(&lp);
            let initial_ir = EmptyIr::<Backend>::new_empty(tree);

            let planned_ir = initial_ir.apply_local_pass_parallel(&planning_pass);

            let verifier_tracking_pass =
                VerifierTrackingPass::<Backend>::new(arg_verifier.clone(), CtxOracles::default());
            let tracked_ir = planned_ir.apply_local_pass_sequential(&verifier_tracking_pass);
            let verifier_virtualization_pass =
                VerifierVirtualizationPass::<Backend>::new(&tracked_ir);
            let virtualized_ir =
                tracked_ir.apply_local_pass_sequential(&verifier_virtualization_pass);
            let gadget_ir_view = crate::verifier::irs::VirtualizedIr::new(
                virtualized_ir.tree().clone(),
                virtualized_ir.payloads().clone(),
            );
            let gadget_initialization_pass = VerifierGadgetInitializationPass::<Backend>::new(
                gadget_ir_view,
                arg_verifier.clone(),
            );
            let gadget_ready_ir =
                virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);
            println!("Planned Query: {query}");
            println!("{}", gadget_ready_ir.display_graphviz(true));
        }
    }

    #[tokio::test]
    async fn verify() {
        for query in queries() {
            // Create a prover and a verifier
            let (mut arg_prover, mut arg_verifier) = test_prelude::<Backend>().unwrap();
            let proof = perform_prover_passes(query, &mut arg_prover).await;
            arg_verifier.set_proof(proof);

            let ctx = SessionContext::new();
            register_dummy_table(&ctx);

            let planning_pass = OutputPlanningPass::<Backend>::new();

            let df = ctx.sql(query).await.unwrap();
            let lp = df.into_unoptimized_plan();
            let tree = Tree::from_logical_plan(&lp);
            let initial_ir = EmptyIr::<Backend>::new_empty(tree);

            let planned_ir = initial_ir.apply_local_pass_parallel(&planning_pass);

            let verifier_tracking_pass =
                VerifierTrackingPass::<Backend>::new(arg_verifier.clone(), CtxOracles::default());
            let tracked_ir = planned_ir.apply_local_pass_sequential(&verifier_tracking_pass);
            let verifier_virtualization_pass =
                VerifierVirtualizationPass::<Backend>::new(&tracked_ir);
            let virtualized_ir =
                tracked_ir.apply_local_pass_sequential(&verifier_virtualization_pass);
            let gadget_ir_view = crate::verifier::irs::VirtualizedIr::new(
                virtualized_ir.tree().clone(),
                virtualized_ir.payloads().clone(),
            );
            let gadget_initialization_pass = VerifierGadgetInitializationPass::<Backend>::new(
                gadget_ir_view,
                arg_verifier.clone(),
            );
            let gadget_ready_ir =
                virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);
            let verify_ir_view = crate::verifier::irs::GadgetReadyIr::new(
                gadget_ready_ir.tree().clone(),
                gadget_ready_ir.payloads().clone(),
            );
            let verify_pass = VerifyPass::<Backend>::new(arg_verifier.clone(), verify_ir_view);
            let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&verify_pass);
            arg_verifier.verify().expect("verifier should verify proof");
            println!("Planned Query: {query}");
            println!("{}", gadget_ready_ir.display_graphviz(true));
        }
    }
}

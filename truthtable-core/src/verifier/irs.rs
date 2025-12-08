//! Intermediate representations (IRs) for the verifier’s truth-table pipeline.
//!
//! This module defines type aliases for the various IRs the verifier's pipeline, ranging from simple plans for computing the witnesses to fully arithmetized and tracked polynomials ready for a SNARK verifier.

use crate::{
    irs::ir::Ir,
    verifier::payloads::{TrackedPayload, VirtualizedPayload},
};

/// The tracked Intermediate Representation with tracked table payloads.
///
/// This IR represents the stage in the verifier's pipeline where the proof tree nodes contain tracked tables; i.e. tables that have commited polynomials and already appended to the verifier's transcript.
pub type TrackedIr<B> = Ir<B, TrackedPayload<B>>;
/// The virtualized Intermediate Representation with virtualized table payloads.
///
/// This IR represents the final stage in the verifier's pipeline where the virtual witnesses were added to the proof tree nodes.
pub type VirtualizedIr<B> = Ir<B, VirtualizedPayload<B>>;

#[cfg(test)]
mod test {
    use super::*;
    use crate::irs::{payloads::HintDFPayload, tree::Tree};
    use crate::prover::passes::planning::PlanningPass;
    use crate::verifier::passes::{tracking::TrackingPass, virtualization::VirtualizationPass};
    use ark_piop::{
        DefaultSnarkBackend, SnarkBackend,
        pcs::{PCS, PolynomialCommitment},
        prover::structs::proof::SNARKProof,
        structs::TrackerID,
        test_utils::test_prelude,
        verifier::ArgVerifier,
    };
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

    fn verifier_with_dummy_proof(num_commitments: usize) -> ArgVerifier<Backend> {
        let (_, mut verifier) = test_prelude::<Backend>().unwrap();
        let mut proof = SNARKProof::<Backend>::default();
        for id in 0..num_commitments {
            let mut commitment = Commitment::default();
            commitment.set_log_size(1);
            proof
                .mv_pcs_subproof
                .comitments
                .insert(TrackerID(id), commitment);
        }
        verifier.set_proof(proof);
        verifier
    }

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

    #[tokio::test]
    async fn builds_tracked_ir_from_logical_plan() {
        let ctx = SessionContext::new();
        register_dummy_table(&ctx);
        let planning_pass = PlanningPass::<Backend>::new();

        for query in queries() {
            let df = ctx.sql(query).await.unwrap();
            let lp = df.into_unoptimized_plan();

            let tree = Tree::from_logical_plan(&lp);
            let initial_ir = Ir::<Backend, crate::irs::payloads::EmptyPayload>::new_empty(tree);
            let planned_ir = initial_ir.apply_local_pass_sequential(&planning_pass);

            let num_commitments = count_materialized_columns(&planned_ir);
            let verifier = verifier_with_dummy_proof(num_commitments);
            let tracking_pass = TrackingPass::<Backend>::new(verifier);
            let tracked_ir = planned_ir.apply_local_pass_sequential(&tracking_pass);

            println!("Tracked Query: {query}");
            println!("{}", tracked_ir.display_graphviz(true));
            assert_eq!(tracked_ir.payloads().len(), tracked_ir.tree().arena().len());
        }
    }

    #[tokio::test]
    async fn builds_virtualized_ir_from_logical_plan() {
        let ctx = SessionContext::new();
        register_dummy_table(&ctx);
        let planning_pass = PlanningPass::<Backend>::new();

        for query in queries() {
            let df = ctx.sql(query).await.unwrap();
            let lp = df.into_unoptimized_plan();

            let tree = Tree::from_logical_plan(&lp);
            let initial_ir = Ir::<Backend, crate::irs::payloads::EmptyPayload>::new_empty(tree);
            let planned_ir = initial_ir.apply_local_pass_sequential(&planning_pass);

            let num_commitments = count_materialized_columns(&planned_ir);
            let verifier = verifier_with_dummy_proof(num_commitments);
            let tracking_pass = TrackingPass::<Backend>::new(verifier);
            let tracked_ir = planned_ir.apply_local_pass_sequential(&tracking_pass);
            let virtualization_pass = VirtualizationPass::<Backend>::new(&tracked_ir);
            let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);

            println!("Virtualized Query: {query}");
            println!("{}", virtualized_ir.display_graphviz(true));
            assert_eq!(
                virtualized_ir.payloads().len(),
                virtualized_ir.tree().arena().len()
            );
        }
    }
}

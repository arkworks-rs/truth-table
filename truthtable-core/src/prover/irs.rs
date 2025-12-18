//! Intermediate representations (IRs) for the prover’s truth-table pipeline.
//!
//! This module defines type aliases for the various IRs the prover's pipeline, ranging from simple plans for computing the witnesses to fully arithmetized and tracked polynomials ready for a SNARK prover.

use crate::{
    irs::ir::Ir,
    prover::payloads::{
        ArithPayload, GadgetReadyPayload, MaterializedPayload, TrackedPayload, VirtualizedPayload,
    },
};
use ark_piop::SnarkBackend;

/// The materialized Intermediate Representation with materialized in-memory table payloads.
///
/// This IR represents the stage in the prover's pipeline where the proof tree nodes contain materialized in-memory tables resulting from executing the hint dataframes.
pub type MaterializedIr<B> = Ir<B, MaterializedPayload>;
/// The arithmetized Intermediate Representation with polynomial payloads.
///
/// This IR represents the stage in the prover's pipeline where the proof tree nodes contain arithmetized polynomials derived from the materialized tables.
pub type ArithmetizedIr<B> = Ir<B, ArithPayload<<B as SnarkBackend>::F>>;
/// The tracked Intermediate Representation with tracked table payloads.
///
/// This IR represents the stage in the prover's pipeline where the proof tree nodes contain tracked tables; i.e. tables that have commited polynomials and already appended to the prover's transcript.
pub type TrackedIr<B> = Ir<B, TrackedPayload<B>>;
/// The virtualized Intermediate Representation with virtualized table payloads.
///
/// This IR represents the final stage in the prover's pipeline where the virtual witnesses were added to the proof tree nodes.
pub type VirtualizedIr<B> = Ir<B, VirtualizedPayload<B>>;
pub type GadgetReadyIr<B> = Ir<B, GadgetReadyPayload<B>>;

#[cfg(test)]
mod test {
    use super::*;
    use crate::irs::payloads::EmptyPayload;
    use crate::prover::passes::arithmetization::ArithmetizationPass;
    use crate::prover::passes::gadget_initialization::GadgetInitializationPass;
    use crate::prover::passes::planning::PlanningPass;
    use crate::prover::passes::proving::ProvingPass;
    use crate::prover::passes::tracking::TrackingPass;
    use crate::prover::passes::virtualization::VirtualizationPass;
    use crate::{irs::tree::Tree, prover::passes::materialization::MaterializationPass};
    use arithmetic::ACTIVATOR_FIELD;
    use ark_piop::DefaultSnarkBackend;
    use ark_piop::test_utils::test_prelude;
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

    fn dummy_schema() -> Arc<Schema> {
        Arc::new(Schema::new(vec![
            Field::new("first_column", DataType::Int32, false),
            Field::new("second_column", DataType::Int32, false),
            Field::new("third_column", DataType::Int32, false),
            (**ACTIVATOR_FIELD).clone(),
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
                Arc::new(BooleanArray::from(vec![true, true, false, true])),
            ],
        )
        .unwrap();
        ctx.register_batch("dummy_table", batch).unwrap();
    }

    fn queries() -> Vec<&'static str> {
        vec![
            "SELECT first_column, second_column FROM dummy_table ",
            "SELECT first_column, second_column FROM dummy_table where third_column = 100",
        ]
    }
    #[tokio::test]
    async fn builds_initial_ir_from_logical_plan() {
        let ctx = SessionContext::new();
        register_dummy_table(&ctx);

        for query in queries() {
            let df = ctx.sql(query).await.unwrap();
            let lp = df.into_unoptimized_plan();

            let tree = Tree::from_logical_plan(&lp);
            let ir = Ir::<DefaultSnarkBackend, EmptyPayload>::new_empty(tree);
            println!("Query: {query}");
            println!("{}", ir.display_graphviz(true));
            assert!(!ir.tree().arena().is_empty());
        }
    }

    #[tokio::test]
    async fn builds_planned_ir_from_logical_plan() {
        let ctx = SessionContext::new();
        register_dummy_table(&ctx);
        let planning_pass = PlanningPass::<DefaultSnarkBackend>::new();

        for query in queries() {
            let df = ctx.sql(query).await.unwrap();
            let lp = df.into_unoptimized_plan();

            let tree = Tree::from_logical_plan(&lp);
            let initial_ir = Ir::<DefaultSnarkBackend, EmptyPayload>::new_empty(tree);
            let planned_ir = initial_ir.apply_local_pass_sequential(&planning_pass);

            println!("Planned Query: {query}");
            println!("{}", planned_ir.display_graphviz(true));
            assert!(!planned_ir.tree().arena().is_empty());
            assert_eq!(planned_ir.payloads().len(), planned_ir.tree().arena().len());
        }
    }

    #[tokio::test]
    async fn builds_materialized_ir_from_logical_plan() {
        for query in queries() {
            let ctx = SessionContext::new();
            register_dummy_table(&ctx);
            let planning_pass = PlanningPass::<DefaultSnarkBackend>::new();
            let materialization_pass = MaterializationPass::<DefaultSnarkBackend>::new();

            let df = ctx.sql(query).await.unwrap();
            let lp = df.into_unoptimized_plan();

            let tree = Tree::from_logical_plan(&lp);
            let initial_ir = Ir::<DefaultSnarkBackend, EmptyPayload>::new_empty(tree);
            let planned_ir = initial_ir.apply_local_pass_sequential(&planning_pass);
            let materialized_ir = planned_ir.apply_local_pass_sequential(&materialization_pass);

            println!("Planned Query: {query}");
            println!("{}", materialized_ir.display_graphviz(true));
        }
    }

    #[tokio::test]
    async fn builds_arithmetized_ir_from_logical_plan() {
        for query in queries() {
            let ctx = SessionContext::new();
            register_dummy_table(&ctx);
            let planning_pass = PlanningPass::<DefaultSnarkBackend>::new();
            let materialization_pass = MaterializationPass::<DefaultSnarkBackend>::new();
            let arithmetization_pass = ArithmetizationPass::<DefaultSnarkBackend>::new();

            let df = ctx.sql(query).await.unwrap();
            let lp = df.into_unoptimized_plan();

            let tree = Tree::from_logical_plan(&lp);
            let initial_ir = Ir::<DefaultSnarkBackend, EmptyPayload>::new_empty(tree);
            let planned_ir = initial_ir.apply_local_pass_sequential(&planning_pass);
            let materialized_ir = planned_ir.apply_local_pass_sequential(&materialization_pass);
            let arithmetized_ir =
                materialized_ir.apply_local_pass_sequential(&arithmetization_pass);

            println!("Planned Query: {query}");
            println!("{}", arithmetized_ir.display_graphviz(true));
        }
    }

    #[tokio::test]
    async fn builds_tracked_ir_from_logical_plan() {
        for query in queries() {
            let (arg_prover, _) = test_prelude().unwrap();
            let ctx = SessionContext::new();
            register_dummy_table(&ctx);
            let planning_pass = PlanningPass::<DefaultSnarkBackend>::new();
            let materialization_pass = MaterializationPass::<DefaultSnarkBackend>::new();
            let arithmetization_pass = ArithmetizationPass::<DefaultSnarkBackend>::new();
            let tracking_pass = TrackingPass::<DefaultSnarkBackend>::new(arg_prover);

            let df = ctx.sql(query).await.unwrap();
            let lp = df.into_unoptimized_plan();

            let tree = Tree::from_logical_plan(&lp);
            let initial_ir = Ir::<DefaultSnarkBackend, EmptyPayload>::new_empty(tree);
            let planned_ir = initial_ir.apply_local_pass_parallel(&planning_pass);
            let materialized_ir = planned_ir.apply_local_pass_parallel(&materialization_pass);
            let arithmetized_ir = materialized_ir.apply_local_pass_parallel(&arithmetization_pass);
            let tracked_ir = arithmetized_ir.apply_local_pass_sequential(&tracking_pass);
            println!("Planned Query: {query}");
            println!("{}", tracked_ir.display_graphviz(true));
        }
    }

    #[tokio::test]
    async fn builds_virtualized_ir_from_logical_plan() {
        for query in queries() {
            let (arg_prover, _) = test_prelude().unwrap();
            let ctx = SessionContext::new();
            register_dummy_table(&ctx);
            let planning_pass = PlanningPass::<DefaultSnarkBackend>::new();
            let materialization_pass = MaterializationPass::<DefaultSnarkBackend>::new();
            let arithmetization_pass = ArithmetizationPass::<DefaultSnarkBackend>::new();
            let tracking_pass = TrackingPass::<DefaultSnarkBackend>::new(arg_prover);

            let df = ctx.sql(query).await.unwrap();
            let lp = df.into_unoptimized_plan();

            let tree = Tree::from_logical_plan(&lp);
            let initial_ir = Ir::<DefaultSnarkBackend, EmptyPayload>::new_empty(tree);
            let planned_ir = initial_ir.apply_local_pass_parallel(&planning_pass);
            let materialized_ir = planned_ir.apply_local_pass_parallel(&materialization_pass);
            let arithmetized_ir = materialized_ir.apply_local_pass_parallel(&arithmetization_pass);
            let tracked_ir = arithmetized_ir.apply_local_pass_sequential(&tracking_pass);
            let virtualization_pass = VirtualizationPass::<DefaultSnarkBackend>::new(&tracked_ir);
            let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);
            println!("Planned Query: {query}");
            println!("{}", virtualized_ir.display_graphviz(true));
        }
    }

    #[tokio::test]
    async fn builds_gadget_ready_ir_from_logical_plan() {
        for query in queries() {
            let (arg_prover, _) = test_prelude().unwrap();
            let ctx = SessionContext::new();
            register_dummy_table(&ctx);
            let planning_pass = PlanningPass::<DefaultSnarkBackend>::new();
            let materialization_pass = MaterializationPass::<DefaultSnarkBackend>::new();
            let arithmetization_pass = ArithmetizationPass::<DefaultSnarkBackend>::new();
            let tracking_pass = TrackingPass::<DefaultSnarkBackend>::new(arg_prover);

            let df = ctx.sql(query).await.unwrap();
            let lp = df.into_unoptimized_plan();

            let tree = Tree::from_logical_plan(&lp);
            let initial_ir = Ir::<DefaultSnarkBackend, EmptyPayload>::new_empty(tree);
            let planned_ir = initial_ir.apply_local_pass_parallel(&planning_pass);
            let materialized_ir = planned_ir.apply_local_pass_parallel(&materialization_pass);
            let arithmetized_ir = materialized_ir.apply_local_pass_parallel(&arithmetization_pass);
            let tracked_ir = arithmetized_ir.apply_local_pass_sequential(&tracking_pass);
            let virtualization_pass = VirtualizationPass::<DefaultSnarkBackend>::new(&tracked_ir);
            let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);

            let gadget_ir_view = crate::prover::irs::VirtualizedIr::new(
                virtualized_ir.tree().clone(),
                virtualized_ir.payloads().clone(),
            );
            let gadget_initialization_pass =
                GadgetInitializationPass::<DefaultSnarkBackend>::new(gadget_ir_view);
            let gadget_ready_ir =
                virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);

            println!("Planned Query: {query}");
            println!("{}", gadget_ready_ir.display_graphviz(true));
        }
    }

    #[tokio::test]
    async fn prove() {
        for query in queries() {
            let (arg_prover, _) = test_prelude().unwrap();
            let ctx = SessionContext::new();
            register_dummy_table(&ctx);
            let planning_pass = PlanningPass::<DefaultSnarkBackend>::new();
            let materialization_pass = MaterializationPass::<DefaultSnarkBackend>::new();
            let arithmetization_pass = ArithmetizationPass::<DefaultSnarkBackend>::new();
            let tracking_pass = TrackingPass::<DefaultSnarkBackend>::new(arg_prover.clone());

            let df = ctx.sql(query).await.unwrap();
            let lp = df.into_unoptimized_plan();
            let tree = Tree::from_logical_plan(&lp);
            let initial_ir = Ir::<DefaultSnarkBackend, EmptyPayload>::new_empty(tree);
            let planned_ir = initial_ir.apply_local_pass_parallel(&planning_pass);
            let materialized_ir = planned_ir.apply_local_pass_parallel(&materialization_pass);
            let arithmetized_ir = materialized_ir.apply_local_pass_parallel(&arithmetization_pass);
            let tracked_ir = arithmetized_ir.apply_local_pass_sequential(&tracking_pass);
            let virtualization_pass = VirtualizationPass::<DefaultSnarkBackend>::new(&tracked_ir);
            let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);
            let gadget_ir_view = crate::prover::irs::VirtualizedIr::new(
                virtualized_ir.tree().clone(),
                virtualized_ir.payloads().clone(),
            );
            let gadget_initialization_pass =
                GadgetInitializationPass::<DefaultSnarkBackend>::new(gadget_ir_view);
            let gadget_ready_ir =
                virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);
            let proving_pass = ProvingPass::<DefaultSnarkBackend>::new(arg_prover.clone());
            let final_ir = gadget_ready_ir.apply_local_pass_sequential(&proving_pass);
            println!("Planned Query: {query}");
            println!("{}", final_ir.display_graphviz(true));
        }
    }
}

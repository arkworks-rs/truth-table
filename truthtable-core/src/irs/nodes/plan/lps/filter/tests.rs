use super::*;
use std::sync::Arc;

use arithmetic::table_oracle::TrackedTableOracle;
use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, table::TrackedTable};
use ark_piop::arithmetic::mat_poly::mle::MLE;
use ark_piop::errors::{SnarkError, SnarkResult, assert_soundness_error};
use ark_piop::prover::ArgProver;
use ark_piop::prover::structs::polynomial::TrackedPoly;
use ark_piop::structs::TrackerID;
use ark_piop::test_utils::test_prelude;
use ark_piop::verifier::structs::oracle::TrackedOracle;
use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::array::{ArrayRef, BooleanArray, Int32Array};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::prelude::SessionContext;
use datafusion_common::ScalarValue;
use datafusion_expr::{Expr, Filter, LogicalPlan, col};
use indexmap::IndexMap;

use crate::irs::nodes::Node;
use crate::irs::payloads::PayloadStructure;
use crate::irs::tree::Tree;
use crate::prover::passes::gadget_initialization::GadgetInitializationPass as ProverGadgetInitializationPass;
use crate::prover::passes::proving::ProvingPass;
use crate::prover::passes::virtualization::VirtualizationPass as ProverVirtualizationPass;
use crate::verifier::passes::gadget_initialization::GadgetInitializationPass as VerifierGadgetInitializationPass;
use crate::verifier::passes::verify::VerifyPass;
use crate::verifier::passes::virtualization::VirtualizationPass as VerifierVirtualizationPass;

type Backend = DefaultSnarkBackend;
const LOG_SIZE: usize = 2;
const INPUT_A: [u64; 4] = [1, 2, 3, 4];
const INPUT_B: [u64; 4] = [10, 20, 30, 40];
const INPUT_ACT: [u64; 4] = [1, 1, 1, 1];

fn build_filter_tree(predicate: Expr) -> Tree<Backend> {
    let ctx = SessionContext::new();
    let schema = Arc::new(Schema::new(vec![
        Field::new("a", DataType::Int32, false),
        Field::new("b", DataType::Int32, false),
        Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
    ]));
    let batch = RecordBatch::try_new(
        schema,
        vec![
            Arc::new(Int32Array::from(
                INPUT_A
                    .iter()
                    .map(|value| *value as i32)
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
            Arc::new(Int32Array::from(
                INPUT_B
                    .iter()
                    .map(|value| *value as i32)
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
            Arc::new(BooleanArray::from(
                INPUT_ACT
                    .iter()
                    .map(|value| *value == 1)
                    .collect::<Vec<_>>(),
            )) as ArrayRef,
        ],
    )
    .expect("record batch creation should succeed");
    let input_df = ctx.read_batch(batch).expect("read batch should succeed");
    let filter = Filter::try_new(predicate, Arc::new(input_df.logical_plan().clone()))
        .expect("filter plan should build");
    let plan = LogicalPlan::Filter(filter);
    Tree::from_logical_plan(&plan)
}

fn filter_nodes(
    tree: &Tree<Backend>,
) -> (
    Arc<Node<Backend>>,
    Arc<Node<Backend>>,
    Arc<Node<Backend>>,
    Arc<Node<Backend>>,
) {
    let root = tree.root().clone();
    let children = root.children();
    assert_eq!(children.len(), 3, "filter node should have three children");
    (
        root,
        children[0].clone(),
        children[1].clone(),
        children[2].clone(),
    )
}

fn tracked_poly_from_evals(prover: &mut ArgProver<Backend>, evals: &[u64]) -> TrackedPoly<Backend> {
    let evals = evals
        .iter()
        .map(|value| <Backend as SnarkBackend>::F::from(*value))
        .collect::<Vec<_>>();
    let mle = MLE::from_evaluations_vec(LOG_SIZE, evals);
    prover.track_and_commit_mat_mv_poly(&mle).unwrap()
}

fn build_prover_tables(
    prover: &mut ArgProver<Backend>,
    predicate_evals: &[u64],
) -> (
    TrackedTable<Backend>,
    TrackedTable<Backend>,
    TrackedTable<Backend>,
) {
    assert_eq!(
        predicate_evals.len(),
        1 << LOG_SIZE,
        "predicate evaluations must match log size"
    );

    let field_a = Arc::new(Field::new("a", DataType::Int32, false));
    let field_b = Arc::new(Field::new("b", DataType::Int32, false));
    let field_pred = Arc::new(Field::new("predicate", DataType::Boolean, false));

    let input_schema = Some(Schema::new(vec![
        field_a.as_ref().clone(),
        field_b.as_ref().clone(),
        ACTIVATOR_FIELD.as_ref().clone(),
    ]));
    let predicate_schema = Some(Schema::new(vec![
        field_pred.as_ref().clone(),
        ACTIVATOR_FIELD.as_ref().clone(),
    ]));
    let output_schema = Some(Schema::new(vec![ACTIVATOR_FIELD.as_ref().clone()]));

    let output_evals = predicate_evals
        .iter()
        .zip(INPUT_ACT.iter())
        .map(|(pred, act)| pred * act)
        .collect::<Vec<_>>();

    let input_act = tracked_poly_from_evals(prover, &INPUT_ACT);
    let predicate_values = tracked_poly_from_evals(prover, predicate_evals);
    let output_act = tracked_poly_from_evals(prover, &output_evals);

    let mut input_polys = IndexMap::new();
    input_polys.insert(field_a, tracked_poly_from_evals(prover, &INPUT_A));
    input_polys.insert(field_b, tracked_poly_from_evals(prover, &INPUT_B));
    input_polys.insert(ACTIVATOR_FIELD.clone(), input_act.clone());
    let input_table = TrackedTable::new(input_schema, input_polys, LOG_SIZE);

    let mut predicate_polys = IndexMap::new();
    predicate_polys.insert(field_pred, predicate_values);
    predicate_polys.insert(ACTIVATOR_FIELD.clone(), input_act);
    let predicate_table = TrackedTable::new(predicate_schema, predicate_polys, LOG_SIZE);

    let mut output_polys = IndexMap::new();
    output_polys.insert(ACTIVATOR_FIELD.clone(), output_act);
    let output_table = TrackedTable::new(output_schema, output_polys, LOG_SIZE);

    (input_table, predicate_table, output_table)
}

fn table_oracle_from_tracked_table(
    table: &TrackedTable<Backend>,
    oracle_by_id: &IndexMap<TrackerID, TrackedOracle<Backend>>,
) -> TrackedTableOracle<Backend> {
    let mut oracles = IndexMap::new();
    for (field, poly) in table.tracked_polys_iter() {
        let oracle = oracle_by_id
            .get(&poly.id())
            .expect("missing tracked oracle for polynomial id")
            .clone();
        oracles.insert(field.clone(), oracle);
    }
    TrackedTableOracle::new(table.schema(), oracles, table.log_size())
}

fn run_filter_case(predicate_expr: Expr, predicate_evals: &[u64]) -> SnarkResult<()> {
    let tree = build_filter_tree(predicate_expr);
    let (root, input, predicate, _gadget) = filter_nodes(&tree);
    let (mut prover, mut verifier) = test_prelude::<Backend>().unwrap();

    let (input_table, predicate_table, output_table) =
        build_prover_tables(&mut prover, predicate_evals);

    let mut payloads = tree
        .arena()
        .keys()
        .map(|id| (*id, None))
        .collect::<IndexMap<_, _>>();
    payloads.insert(
        input.id(),
        Some(PayloadStructure::PlanPayload(input_table.clone())),
    );
    payloads.insert(
        predicate.id(),
        Some(PayloadStructure::PlanPayload(predicate_table.clone())),
    );
    payloads.insert(
        root.id(),
        Some(PayloadStructure::PlanPayload(output_table.clone())),
    );

    let tracked_ir = crate::prover::irs::TrackedIr::new(tree.clone(), payloads);
    let virtualization_pass = ProverVirtualizationPass::<Backend>::new(&tracked_ir);
    let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);
    let gadget_ir_view = crate::prover::irs::VirtualizedIr::new(
        virtualized_ir.tree().clone(),
        virtualized_ir.payloads().clone(),
    );
    let gadget_initialization_pass = ProverGadgetInitializationPass::<Backend>::new(gadget_ir_view);
    let gadget_ready_ir = virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);

    let proving_ir_view = crate::prover::irs::GadgetReadyIr::new(
        gadget_ready_ir.tree().clone(),
        gadget_ready_ir.payloads().clone(),
    );
    let proving_pass = ProvingPass::<Backend>::new(prover.clone(), proving_ir_view);
    let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&proving_pass);
    proving_pass.take_result()?;

    let proof = prover.build_proof()?;
    verifier.set_proof(proof);

    let mut tracked_ids = Vec::new();
    for table in [&input_table, &predicate_table, &output_table] {
        for (_, poly) in table.tracked_polys_iter() {
            tracked_ids.push(poly.id());
        }
    }
    tracked_ids.sort();
    tracked_ids.dedup();

    let mut oracle_by_id = IndexMap::new();
    for id in tracked_ids {
        oracle_by_id.insert(id, verifier.track_mv_com_by_id(id)?);
    }

    let input_oracle_table = table_oracle_from_tracked_table(&input_table, &oracle_by_id);
    let predicate_oracle_table = table_oracle_from_tracked_table(&predicate_table, &oracle_by_id);
    let output_oracle_table = table_oracle_from_tracked_table(&output_table, &oracle_by_id);

    let mut verifier_payloads = tree
        .arena()
        .keys()
        .map(|id| (*id, None))
        .collect::<IndexMap<_, _>>();
    verifier_payloads.insert(
        input.id(),
        Some(PayloadStructure::PlanPayload(input_oracle_table)),
    );
    verifier_payloads.insert(
        predicate.id(),
        Some(PayloadStructure::PlanPayload(predicate_oracle_table)),
    );
    verifier_payloads.insert(
        root.id(),
        Some(PayloadStructure::PlanPayload(output_oracle_table)),
    );

    let tracked_ir = crate::verifier::irs::TrackedIr::new(tree, verifier_payloads);
    let virtualization_pass = VerifierVirtualizationPass::<Backend>::new(&tracked_ir);
    let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);
    let gadget_ir_view = crate::verifier::irs::VirtualizedIr::new(
        virtualized_ir.tree().clone(),
        virtualized_ir.payloads().clone(),
    );
    let gadget_initialization_pass =
        VerifierGadgetInitializationPass::<Backend>::new(gadget_ir_view);
    let gadget_ready_ir = virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);

    let verify_ir_view = crate::verifier::irs::GadgetReadyIr::new(
        gadget_ready_ir.tree().clone(),
        gadget_ready_ir.payloads().clone(),
    );
    let verify_pass = VerifyPass::<Backend>::new(verifier.clone(), verify_ir_view);
    let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&verify_pass);
    verify_pass.take_result()?;

    verifier.verify()?;
    Ok(())
}

#[test]
fn completeness_filter_prove_and_verify() {
    let cases = vec![
        (
            col("a").eq(Expr::Literal(ScalarValue::Int32(Some(2)))),
            vec![0_u64, 1, 0, 0],
        ),
        (
            col("b").eq(Expr::Literal(ScalarValue::Int32(Some(30)))),
            vec![0_u64, 0, 1, 0],
        ),
        (col("a").eq(col("b")), vec![0_u64, 0, 0, 0]),
    ];

    for (predicate, evals) in cases {
        run_filter_case(predicate, &evals).unwrap();
    }
}

#[test]
fn soundness_filter_rejects_all_true_predicate() {
    let predicate = col("a").eq(Expr::Literal(ScalarValue::Int32(Some(2))));
    let evals = vec![1_u64, 1, 1, 1];
    let err = run_filter_case(predicate, &evals).unwrap_err();
    assert_soundness_error(err);
}

#[test]
fn soundness_filter_rejects_all_false_predicate() {
    let predicate = col("a").eq(Expr::Literal(ScalarValue::Int32(Some(2))));
    let evals = vec![0_u64, 0, 0, 0];
    let err = run_filter_case(predicate, &evals).unwrap_err();
    assert_soundness_error(err);
}

#[test]
fn completeness_filter_geq_two() {
    let predicate = col("a").gt_eq(Expr::Literal(ScalarValue::Int32(Some(2))));
    let evals = vec![0_u64, 1, 1, 1];
    run_filter_case(predicate, &evals).unwrap();
}

#[test]
fn soundness_filter_geq_two_rejects_false_positive() {
    let predicate = col("a").gt_eq(Expr::Literal(ScalarValue::Int32(Some(2))));
    let evals = vec![1_u64, 1, 1, 1];
    let err = run_filter_case(predicate, &evals).unwrap_err();
    assert_soundness_error(err);
}

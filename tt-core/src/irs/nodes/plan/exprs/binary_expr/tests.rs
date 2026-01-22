use super::*;
use std::sync::Arc;

use arithmetic::ACTIVATOR_COL_NAME;
use arithmetic::table::TrackedTable;
use arithmetic::table_oracle::TrackedTableOracle;
use ark_piop::arithmetic::mat_poly::mle::MLE;
use ark_piop::errors::SnarkResult;
use ark_piop::prover::ArgProver;
use ark_piop::prover::structs::polynomial::TrackedPoly;
use ark_piop::structs::TrackerID;
use ark_piop::test_utils::test_prelude;
use ark_piop::verifier::structs::oracle::TrackedOracle;
use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::array::{ArrayRef, BooleanArray, Int32Array};
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::prelude::SessionContext;
use datafusion_common::ScalarValue;
use datafusion_expr::{Expr, col};
use indexmap::IndexMap;
type Backend = DefaultSnarkBackend;
const LOG_SIZE: usize = 2;
const INPUT_A: [u64; 4] = [1, 2, 3, 4];
const INPUT_B: [u64; 4] = [10, 20, 30, 40];
const INPUT_ACT: [u64; 4] = [1, 1, 1, 1];

fn tracked_poly_from_evals(prover: &mut ArgProver<Backend>, evals: &[u64]) -> TrackedPoly<Backend> {
    let evals = evals
        .iter()
        .map(|value| <Backend as SnarkBackend>::F::from(*value))
        .collect::<Vec<_>>();
    let mle = MLE::from_evaluations_vec(LOG_SIZE, evals);
    prover.track_and_commit_mat_mv_poly(&mle).unwrap()
}

#[allow(clippy::complexity)]
fn build_projection_tree(
    expr: Expr,
) -> (
    Tree<Backend>,
    Arc<Node<Backend>>,
    Arc<Node<Backend>>,
    Arc<Node<Backend>>,
) {
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
    let df = ctx.read_batch(batch).expect("read batch should succeed");
    let projected = df.select(vec![expr]).expect("projection should build");
    let plan = projected.logical_plan().clone();
    let tree = Tree::from_logical_plan(&plan);
    let root = tree.root().clone();
    let mut input = None;
    let mut expr_node = None;
    for child in root.children() {
        match child.name().as_str() {
            "TableScan" => input = Some(child.clone()),
            "BinaryExpr" => expr_node = Some(child.clone()),
            _ => {}
        }
    }
    let input = input.expect("projection should include table scan input");
    let expr_node = expr_node.expect("projection should include binary expr node");
    (tree, root, input, expr_node)
}

fn output_field_from_expr(expr_node: &Arc<Node<Backend>>) -> FieldRef {
    match expr_node.as_ref() {
        Node::Plan(plan_node) => plan_node
            .output()
            .data_frame()
            .schema()
            .fields()
            .iter()
            .find(|field| !arithmetic::is_system_column(field.name()))
            .cloned()
            .expect("BinaryExpr output should include a data column"),
        _ => panic!("Expected plan node for binary expression root"),
    }
}

fn build_input_table(prover: &mut ArgProver<Backend>) -> TrackedTable<Backend> {
    let field_a = Arc::new(Field::new("a", DataType::Int32, false));
    let field_b = Arc::new(Field::new("b", DataType::Int32, false));

    let schema = Some(Schema::new(vec![
        field_a.as_ref().clone(),
        field_b.as_ref().clone(),
        (**ACTIVATOR_FIELD).clone(),
    ]));

    let mut polys = IndexMap::new();
    polys.insert(field_a, tracked_poly_from_evals(prover, &INPUT_A));
    polys.insert(field_b, tracked_poly_from_evals(prover, &INPUT_B));
    polys.insert(
        ACTIVATOR_FIELD.clone(),
        tracked_poly_from_evals(prover, &INPUT_ACT),
    );

    TrackedTable::new(schema, polys, LOG_SIZE)
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

fn end_to_end_binary_expr(expr: Expr, output_evals: &[u64]) -> SnarkResult<()> {
    assert_eq!(
        output_evals.len(),
        1 << LOG_SIZE,
        "output evaluations must match log size"
    );

    let (tree, _root, input, expr_node) = build_projection_tree(expr);
    let (mut prover, mut verifier) = test_prelude::<Backend>().unwrap();

    let input_table = build_input_table(&mut prover);
    let output_field = output_field_from_expr(&expr_node);
    let output_poly = tracked_poly_from_evals(&mut prover, output_evals);
    let output_activator = input_table
        .activator_tracked_poly()
        .expect("input table should include activator");
    let output_table = TrackedTable::single_column_with_activator(
        output_field,
        output_poly,
        Some(output_activator),
    );

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
        expr_node.id(),
        Some(PayloadStructure::PlanPayload(output_table.clone())),
    );

    let tracked_ir = crate::prover::irs::TrackedIr::new(tree.clone(), payloads);
    let virtualization_pass =
        crate::prover::passes::virtualization::VirtualizationPass::<Backend>::new(&tracked_ir);
    let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);
    let gadget_ir_view = crate::prover::irs::VirtualizedIr::new(
        virtualized_ir.tree().clone(),
        virtualized_ir.payloads().clone(),
    );
    let gadget_initialization_pass =
        crate::prover::passes::gadget_initialization::GadgetInitializationPass::<Backend>::new(
            gadget_ir_view,
            prover.clone(),
        );
    let gadget_ready_ir = virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);

    let proving_ir_view = crate::prover::irs::GadgetReadyIr::new(
        gadget_ready_ir.tree().clone(),
        gadget_ready_ir.payloads().clone(),
    );
    let proving_pass = crate::prover::passes::proving::ProvingPass::<Backend>::new(
        prover.clone(),
        proving_ir_view,
    );
    let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&proving_pass);
    proving_pass.take_result()?;

    let proof = prover.build_proof()?;
    verifier.set_proof(proof);

    let mut tracked_ids = Vec::new();
    for table in [&input_table, &output_table] {
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
        expr_node.id(),
        Some(PayloadStructure::PlanPayload(output_oracle_table)),
    );

    let tracked_ir = crate::verifier::irs::TrackedIr::new(tree, verifier_payloads);
    let virtualization_pass =
        crate::verifier::passes::virtualization::VirtualizationPass::<Backend>::new(&tracked_ir);
    let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);
    let gadget_ir_view = crate::verifier::irs::VirtualizedIr::new(
        virtualized_ir.tree().clone(),
        virtualized_ir.payloads().clone(),
    );
    let gadget_initialization_pass =
        crate::verifier::passes::gadget_initialization::GadgetInitializationPass::<Backend>::new(
            gadget_ir_view,
            verifier.clone(),
        );
    let gadget_ready_ir = virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);

    let verify_ir_view = crate::verifier::irs::GadgetReadyIr::new(
        gadget_ready_ir.tree().clone(),
        gadget_ready_ir.payloads().clone(),
    );
    let verify_pass = crate::verifier::passes::verify::VerifyPass::<Backend>::new(
        verifier.clone(),
        verify_ir_view,
    );
    let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&verify_pass);
    verify_pass.take_result()?;

    verifier.verify()?;
    Ok(())
}

#[test]
fn end_to_end_binary_expr_eq() {
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

    for (expr, evals) in cases {
        end_to_end_binary_expr(expr, &evals).unwrap();
    }
}

#[test]
fn end_to_end_binary_expr_geq() {
    let cases = vec![
        (
            col("a").gt_eq(Expr::Literal(ScalarValue::Int32(Some(2)))),
            vec![0_u64, 1, 1, 1],
        ),
        (
            col("b").gt_eq(Expr::Literal(ScalarValue::Int32(Some(20)))),
            vec![0_u64, 1, 1, 1],
        ),
    ];

    for (expr, evals) in cases {
        end_to_end_binary_expr(expr, &evals).unwrap();
    }
}

#[test]
fn end_to_end_binary_expr_leq() {
    let cases = vec![
        (
            col("a").lt_eq(Expr::Literal(ScalarValue::Int32(Some(2)))),
            vec![1_u64, 1, 0, 0],
        ),
        (
            col("b").lt_eq(Expr::Literal(ScalarValue::Int32(Some(30)))),
            vec![1_u64, 1, 1, 0],
        ),
    ];

    for (expr, evals) in cases {
        end_to_end_binary_expr(expr, &evals).unwrap();
    }
}

#[test]
fn end_to_end_binary_expr_gt() {
    let cases = vec![
        (
            col("a").gt(Expr::Literal(ScalarValue::Int32(Some(2)))),
            vec![0_u64, 0, 1, 1],
        ),
        (
            col("b").gt(Expr::Literal(ScalarValue::Int32(Some(20)))),
            vec![0_u64, 0, 1, 1],
        ),
    ];

    for (expr, evals) in cases {
        end_to_end_binary_expr(expr, &evals).unwrap();
    }
}

#[test]
fn end_to_end_binary_expr_lt() {
    let cases = vec![
        (
            col("a").lt(Expr::Literal(ScalarValue::Int32(Some(3)))),
            vec![1_u64, 1, 0, 0],
        ),
        (
            col("b").lt(Expr::Literal(ScalarValue::Int32(Some(30)))),
            vec![1_u64, 1, 0, 0],
        ),
    ];

    for (expr, evals) in cases {
        end_to_end_binary_expr(expr, &evals).unwrap();
    }
}

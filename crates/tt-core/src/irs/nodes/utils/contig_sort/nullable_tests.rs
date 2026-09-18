//! Schema-level NULL policy, exercised independently on both protocol sides.
use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_FIELD, ROW_ID_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, errors::SnarkError, test_utils::prelude_with_vars,
};
use datafusion::arrow::{
    array::{Array, ArrayRef, BooleanArray, Int8Array, Int64Array},
    datatypes::{DataType, Field, Schema},
    record_batch::RecordBatch,
};
use datafusion::prelude::SessionContext;
use indexmap::IndexMap;

use super::{
    DIFF_INPUT_LABEL, GadgetNode, ROTATED_INPUT_LABEL, SortConfig, TABLE_LABEL, UniformConfig,
    checked_difference_field, pad_batches_to_power_of_two,
};
use crate::irs::{
    ir::Ir,
    nodes::{Node, ProverNodeOps, VerifierNodeOps, hints::HintDF},
    payloads::PayloadStructure,
    shared_ir::OutputPlannedIr,
    tree::Tree,
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

fn assert_nullable_error(error: SnarkError) {
    assert!(
        matches!(error,
        SnarkError::DataTypeError(
            ark_piop::arithmetic::errors::DataTypeError::NotSupported(message))
            if message.contains("non-nullable sort keys")),
        "expected the explicit nullable-source rejection"
    );
}
fn gadget() -> Arc<GadgetNode<B>> {
    Arc::new(GadgetNode::new(SortConfig::Uniform(UniformConfig {
        asc: true,
        strict: false,
    })))
}
fn source_batch(nullable: bool, values: Vec<Option<i8>>) -> RecordBatch {
    let n = values.len();
    RecordBatch::try_new(
        Arc::new(Schema::new(vec![
            Arc::new(Field::new("key", DataType::Int8, nullable)),
            ACTIVATOR_FIELD.clone(),
            Arc::new(Field::new(ROW_ID_COL_NAME, DataType::Int64, false)),
        ])),
        vec![
            Arc::new(Int8Array::from(values)),
            Arc::new(BooleanArray::from(vec![true; n])),
            Arc::new(Int64Array::from((0..n as i64).collect::<Vec<_>>())),
        ],
    )
    .unwrap()
}
fn plan_source(batch: RecordBatch, is_verifier: bool) -> Result<OutputPlannedIr<B>, SnarkError> {
    let g = gadget();
    let node = Arc::new(Node::Gadget(g.clone()));
    let id = node.id();
    let hint = HintDF::new_materialized(SessionContext::new().read_batch(batch).unwrap());
    let mut ir = Ir::new_empty(Tree::new_from_root(node));
    ir.set_payload_for_node(
        id,
        Some(PayloadStructure::GadgetPayload(IndexMap::from([(
            TABLE_LABEL.to_string(),
            hint,
        )]))),
    );
    if is_verifier {
        VerifierNodeOps::initialize_gadget_plans(g.as_ref(), id, &mut ir)?;
    } else {
        ProverNodeOps::initialize_gadget_plans(g.as_ref(), id, &mut ir)?;
    }
    Ok(ir)
}
#[test]
fn nullable_policy_checks_source_field_not_only_arrow_type() {
    for data_type in [
        DataType::Int8,
        DataType::Int64,
        DataType::UInt64,
        DataType::Date32,
    ] {
        assert_nullable_error(
            checked_difference_field::<B>(&Field::new("key", data_type.clone(), true)).unwrap_err(),
        );
        assert!(checked_difference_field::<B>(&Field::new("key", data_type, false)).is_ok());
    }
}
#[test]
fn nullable_policy_rejects_planning_on_both_sides_even_without_null_values() {
    for is_verifier in [false, true] {
        for values in [
            vec![None, Some(1)],
            vec![Some(1), None],
            vec![Some(1), Some(2)],
        ] {
            let result = plan_source(source_batch(true, values), is_verifier);
            match result {
                Err(error) => assert_nullable_error(error),
                Ok(_) => panic!("nullable keys must be rejected by either planner"),
            }
        }
    }
}
#[test]
fn nullable_policy_preserves_nonnullable_source_through_normal_planning_and_padding() {
    for is_verifier in [false, true] {
        let ir = plan_source(
            source_batch(false, vec![Some(1), Some(2), Some(3)]),
            is_verifier,
        )
        .unwrap();
        let root = ir.tree().root().id();
        let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&root) else {
            panic!("expected gadget payload");
        };
        let input = payload.get(TABLE_LABEL).unwrap();
        let field = input
            .data_frame()
            .schema()
            .field_with_unqualified_name("key")
            .unwrap();
        assert!(!field.is_nullable());
        let diff = payload.get(DIFF_INPUT_LABEL).unwrap();
        let diff_field = diff
            .data_frame()
            .schema()
            .field_with_unqualified_name("key")
            .unwrap();
        assert!(
            diff_field.is_nullable(),
            "witness nullability is not source nullability"
        );
        let ties = payload.get(super::TIE_INDICATOR_LABEL).unwrap();
        assert!(
            ties.data_frame()
                .schema()
                .fields()
                .iter()
                .all(|field| !field.is_nullable()),
            "both planners must describe total Boolean tie columns"
        );
        if !is_verifier {
            let batches = super::collect_blocking(input.data_frame().clone()).unwrap();
            assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 4);
            for batch in batches {
                assert_eq!(batch.column_by_name("key").unwrap().null_count(), 0);
            }
        }
    }
}
#[test]
fn nullable_policy_prover_rejects_nullable_source_before_consuming_hints() {
    let (mut prover, _) = prelude_with_vars::<B>(1).unwrap();
    let source_field = Arc::new(Field::new("key", DataType::Int8, true));
    let witness_field = Arc::new(Field::new("key", DataType::Int8, false));
    let poly = prover.track_mat_mv_cnst_poly(1, F::from(1u64));
    let source = TrackedTable::new(None, IndexMap::from([(source_field, poly.clone())]), 1);
    let diff = TrackedTable::new(None, IndexMap::from([(witness_field, poly)]), 1);
    let g = gadget();
    let node = Arc::new(Node::Gadget(g.clone()));
    let id = node.id();
    let mut ir: crate::prover::irs::VirtualizedIr<B> = Ir::new_empty(Tree::new_from_root(node));
    // No tie hint: admission must not depend on comparison hint availability.
    ir.set_payload_for_node(
        id,
        Some(PayloadStructure::GadgetPayload(IndexMap::from([
            (TABLE_LABEL.to_string(), source.clone()),
            (ROTATED_INPUT_LABEL.to_string(), source),
            (DIFF_INPUT_LABEL.to_string(), diff),
        ]))),
    );
    assert_nullable_error(
        ProverNodeOps::initialize_gadgets(g.as_ref(), id, &mut prover, &mut ir).unwrap_err(),
    );
}
#[test]
fn nullable_policy_verifier_rejects_without_any_prover_precheck() {
    let (_, mut verifier) = prelude_with_vars::<B>(1).unwrap();
    let source_field = Arc::new(Field::new("key", DataType::Int8, true));
    let witness_field = Arc::new(Field::new("key", DataType::Int8, false));
    let oracle = verifier.track_mat_mv_cnst_oracle(1, F::from(1u64));
    let source = TrackedTableOracle::new(None, IndexMap::from([(source_field, oracle.clone())]), 1);
    let diff = TrackedTableOracle::new(None, IndexMap::from([(witness_field, oracle)]), 1);
    let g = gadget();
    let node = Arc::new(Node::Gadget(g.clone()));
    let id = node.id();
    let mut ir: crate::verifier::irs::VirtualizedIr<B> = Ir::new_empty(Tree::new_from_root(node));
    // These are verifier-side source and witness schemas. No proof is generated,
    // so a prover's rejection cannot masquerade as verifier enforcement.
    ir.set_payload_for_node(
        id,
        Some(PayloadStructure::GadgetPayload(IndexMap::from([
            (TABLE_LABEL.to_string(), source.clone()),
            (ROTATED_INPUT_LABEL.to_string(), source),
            (DIFF_INPUT_LABEL.to_string(), diff),
        ]))),
    );
    assert_nullable_error(
        VerifierNodeOps::initialize_gadgets(g.as_ref(), id, &mut verifier, &mut ir).unwrap_err(),
    );
}
#[test]
fn nullable_policy_empty_padding_preserves_schema_and_uses_nonnull_values() {
    for data_type in [DataType::Int8, DataType::Date32] {
        let schema = Schema::new(vec![
            Arc::new(Field::new("key", data_type.clone(), false)),
            ACTIVATOR_FIELD.clone(),
            Arc::new(Field::new(ROW_ID_COL_NAME, DataType::Int64, false)),
        ]);
        let empty = RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![
                datafusion_common::ScalarValue::new_zero(&data_type)
                    .unwrap()
                    .to_array_of_size(0)
                    .unwrap(),
                Arc::new(BooleanArray::from(Vec::<bool>::new())) as ArrayRef,
                Arc::new(Int64Array::from(Vec::<i64>::new())),
            ],
        )
        .unwrap();
        for batches in [vec![], vec![empty]] {
            let (padded, _) = pad_batches_to_power_of_two(&schema, batches).unwrap();
            assert_eq!(padded.len(), 1);
            assert_eq!(padded[0].num_rows(), 2);
            assert_eq!(padded[0].schema().as_ref(), &schema);
            assert_eq!(padded[0].column(0).null_count(), 0);
            let active = padded[0]
                .column(1)
                .as_any()
                .downcast_ref::<BooleanArray>()
                .unwrap();
            assert!(active.iter().all(|value| value == Some(false)));
        }
    }
}

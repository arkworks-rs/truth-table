//! The sortedness argument must consume the output keys, not a sorted helper.

use std::{collections::HashMap, sync::Arc};

use arithmetic::ACTIVATOR_COL_NAME;
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, errors::SnarkError, verifier::errors::VerifierError,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion_common::{Column, DFSchema, TableReference};
use datafusion_expr::{
    Expr, LogicalPlan, Sort, col, expr::Sort as SortExpr, logical_plan::EmptyRelation,
};

use super::{GadgetNode, INPUT_LABEL, OUTPUT_LABEL, OUTPUT_SORT_EXPRS, validate_sort};
use crate::{
    irs::nodes::{IsNode, Node, ProverNodeOps, utils::contig_sort},
    irs::payloads::PayloadStructure,
    test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline},
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

fn table(name: &str, values: [i64; 4], active: bool) -> TableSpec<F> {
    let field = Arc::new(Field::new(name, DataType::Int64, false));
    let mut fields = vec![field.as_ref().clone()];
    if active {
        // Production key tables carry the activator in both their schema and
        // tracked-column map. Mirror that shape so prescribed-permutation can
        // append its index column without changing their relative order.
        fields.push(arithmetic::ACTIVATOR_FIELD.as_ref().clone());
    }
    TableSpec {
        schema: Schema::new(fields),
        log_size: 2,
        cols: vec![(field, values.into_iter().map(F::from).collect())],
        activator: active.then(|| vec![F::from(1u64); 4]),
    }
}

fn harness(output: [i64; 4], asc: bool) -> GadgetHarness<B> {
    harness_with_optional_keys(output, asc, true)
}

fn validation_sort(
    fields: Vec<(Option<TableReference>, Arc<Field>)>,
    expr: Vec<SortExpr>,
    fetch: Option<usize>,
) -> Sort {
    let schema = DFSchema::new_with_metadata(fields, HashMap::new()).unwrap();
    Sort {
        expr,
        input: Arc::new(LogicalPlan::EmptyRelation(EmptyRelation {
            produce_one_row: false,
            schema: Arc::new(schema),
        })),
        fetch,
    }
}

fn field(name: &str, data_type: DataType, nullable: bool) -> Arc<Field> {
    Arc::new(Field::new(name, data_type, nullable))
}

fn unqualified_key(name: &str) -> SortExpr {
    Expr::Column(Column::new_unqualified(name)).sort(true, false)
}

fn qualified_key(relation: &str, name: &str) -> SortExpr {
    Expr::Column(Column::new(Some(relation), name)).sort(true, false)
}

fn harness_with_optional_keys(
    output: [i64; 4],
    asc: bool,
    include_output_keys: bool,
) -> GadgetHarness<B> {
    // Only the sort specification is consumed by this gadget-level harness.
    // The production validator also resolves each key against this input
    // schema, so keep the isolated fixture faithful to a real non-null key.
    let input_schema =
        DFSchema::try_from(Schema::new(vec![Field::new("key", DataType::Int64, false)])).unwrap();
    let sort = Sort {
        expr: vec![col("key").sort(asc, false)],
        input: Arc::new(LogicalPlan::EmptyRelation(EmptyRelation {
            produce_one_row: false,
            schema: Arc::new(input_schema),
        })),
        fetch: None,
    };
    let gadget = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(sort))));
    let root_id = gadget.id();
    let sort_id = gadget.children()[0].id();
    let sorted = if asc { [1, 2, 3, 4] } else { [4, 3, 2, 1] };
    let rotated = if asc { [2, 3, 4, 1] } else { [3, 2, 1, 4] };

    // Sortcheck composes prescribed permutation, sign, and tie checks; its
    // largest generated polynomial needs more variables than the tiny table.
    let mut builder = GadgetHarness::<B>::builder(16)
        .with_gadget(gadget)
        .with_table(root_id, INPUT_LABEL, table("key", [2, 1, 3, 4], true))
        .with_table(root_id, OUTPUT_LABEL, table("key", output, true));
    if include_output_keys {
        // The LP layer supplies expressions of the actual output here. A
        // separate planning helper must not replace these tracked expressions.
        builder = builder.with_table(root_id, OUTPUT_SORT_EXPRS, table("key", output, true));
    }
    builder
        .with_table(
            sort_id,
            contig_sort::TABLE_LABEL,
            table("key", sorted, true),
        )
        .with_table(
            sort_id,
            contig_sort::ROTATED_INPUT_LABEL,
            table("key", rotated, true),
        )
        .with_table(
            sort_id,
            contig_sort::TIE_INDICATOR_LABEL,
            table("tie_0", [1, 1, 1, 0], false),
        )
        .with_table(
            sort_id,
            contig_sort::DIFF_INPUT_LABEL,
            table("key", [1, 1, 1, -3], false),
        )
        .build()
}

#[test]
fn direct_nonnullable_int64_key_is_supported() {
    let sort = validation_sort(
        vec![(None, field("key", DataType::Int64, false))],
        vec![unqualified_key("key")],
        None,
    );

    assert_eq!(validate_sort(&sort), Ok(()));
}

#[test]
fn empty_key_list_is_rejected() {
    let sort = validation_sort(
        vec![(None, field("key", DataType::Int64, false))],
        Vec::new(),
        None,
    );

    let error = validate_sort(&sort).expect_err("ORDER BY must prove at least one key");
    assert!(error.contains("at least one proved key"));
}

#[test]
fn embedded_fetch_is_rejected() {
    let sort = validation_sort(
        vec![(None, field("key", DataType::Int64, false))],
        vec![unqualified_key("key")],
        Some(1),
    );

    let error = validate_sort(&sort).expect_err("embedded top-k must be normalized first");
    assert!(error.contains("embedded fetch"));
}

#[test]
fn nullable_key_is_rejected() {
    let sort = validation_sort(
        vec![(None, field("key", DataType::Int64, true))],
        vec![unqualified_key("key")],
        None,
    );

    let error = validate_sort(&sort).expect_err("NULL ordering is not proved");
    assert!(error.contains("nullable ORDER BY key"));
}

#[test]
fn system_key_is_rejected() {
    let sort = validation_sort(
        vec![(None, field(ACTIVATOR_COL_NAME, DataType::Boolean, false))],
        vec![unqualified_key(ACTIVATOR_COL_NAME)],
        None,
    );

    let error = validate_sort(&sort).expect_err("internal columns are not SQL sort keys");
    assert!(error.contains("internal system column"));
}

#[test]
fn unsupported_key_type_is_rejected() {
    let sort = validation_sort(
        vec![(None, field("key", DataType::Utf8, false))],
        vec![unqualified_key("key")],
        None,
    );

    let error = validate_sort(&sort).expect_err("string ordering is not proved");
    assert!(error.contains("unsupported ORDER BY key type"));
}

#[test]
fn dotted_key_name_is_rejected() {
    let sort = validation_sort(
        vec![(None, field("quoted.key", DataType::Int64, false))],
        vec![unqualified_key("quoted.key")],
        None,
    );

    let error = validate_sort(&sort).expect_err("literal dots cannot be encoded safely");
    assert!(error.contains("dots in key field names"));
}

#[test]
fn qualified_keys_resolve_exactly_and_duplicate_terminal_names_are_rejected() {
    let qualified_fields = || {
        vec![
            (
                Some(TableReference::bare("l")),
                field("id", DataType::Int64, false),
            ),
            (
                Some(TableReference::bare("r")),
                field("id", DataType::Int64, false),
            ),
        ]
    };

    let right = validation_sort(qualified_fields(), vec![qualified_key("r", "id")], None);
    assert_eq!(validate_sort(&right), Ok(()));

    let missing = validation_sort(qualified_fields(), vec![qualified_key("x", "id")], None);
    let error = validate_sort(&missing).expect_err("a missing qualifier must not fall back");
    assert!(error.contains("does not resolve uniquely"));

    let ambiguous = validation_sort(qualified_fields(), vec![unqualified_key("id")], None);
    let error = validate_sort(&ambiguous).expect_err("an ambiguous key must not pick one side");
    assert!(error.contains("does not resolve uniquely"));

    let duplicate_terminal_names = validation_sort(
        qualified_fields(),
        vec![qualified_key("l", "id"), qualified_key("r", "id")],
        None,
    );
    let error = validate_sort(&duplicate_terminal_names)
        .expect_err("ContiguousSort cannot distinguish equal terminal names");
    assert!(error.contains("duplicate unqualified key names"));
}

#[test]
fn missing_output_key_payload_is_rejected() {
    let mut harness = harness_with_optional_keys([1, 2, 3, 4], true, false);
    let err = ProverNodeOps::initialize_gadgets(
        harness.gadget.as_ref(),
        harness.node_id,
        &mut harness.prover,
        &mut harness.prover_ir,
    )
    .expect_err("ORDER BY must fail closed when its output key is absent");
    assert!(matches!(err, SnarkError::Artifact(_)));
}

#[test]
fn missing_row_permutation_payload_is_rejected() {
    for missing_label in [INPUT_LABEL, OUTPUT_LABEL] {
        let mut harness = harness([1, 2, 3, 4], true);
        let payload = match harness.prover_ir.payload_for_node(&harness.node_id) {
            Some(PayloadStructure::GadgetPayload(payload)) => payload,
            _ => panic!("missing ORDER BY payload"),
        };
        let mut incomplete = payload.clone();
        incomplete.shift_remove(missing_label);
        harness.prover_ir.set_payload_for_node(
            harness.node_id,
            Some(PayloadStructure::GadgetPayload(incomplete)),
        );

        let err = ProverNodeOps::initialize_gadgets(
            harness.gadget.as_ref(),
            harness.node_id,
            &mut harness.prover,
            &mut harness.prover_ir,
        )
        .expect_err("ORDER BY must bind both sides of its row permutation");
        assert!(matches!(err, SnarkError::Artifact(_)));
        assert!(err.to_string().contains(missing_label));
    }
}

#[test]
fn sortcheck_uses_output_key_commitments() {
    let mut harness = harness([2, 1, 3, 4], true);
    let expected = match harness.prover_ir.payload_for_node(&harness.node_id) {
        Some(PayloadStructure::GadgetPayload(payload)) => payload[OUTPUT_SORT_EXPRS]
            .tracked_col_by_ind(0)
            .data_tracked_poly()
            .id(),
        _ => panic!("missing test payload"),
    };
    ProverNodeOps::initialize_gadgets(
        harness.gadget.as_ref(),
        harness.node_id,
        &mut harness.prover,
        &mut harness.prover_ir,
    )
    .unwrap();
    let sort_id = harness.gadget.children()[0].id();
    let actual = match harness.prover_ir.payload_for_node(&sort_id) {
        Some(PayloadStructure::GadgetPayload(payload)) => payload[contig_sort::TABLE_LABEL]
            .tracked_col_by_ind(0)
            .data_tracked_poly()
            .id(),
        _ => panic!("missing sort payload"),
    };
    assert_eq!(actual, expected, "Sortcheck must reuse the output's keys");
}

#[test]
fn sorted_output_is_accepted_in_both_directions() {
    run_gadget_pipeline(harness([1, 2, 3, 4], true)).unwrap();
    run_gadget_pipeline(harness([4, 3, 2, 1], false)).unwrap();
}

#[test]
fn sorted_helper_does_not_validate_unsorted_output() {
    let err = run_gadget_pipeline(harness([2, 1, 3, 4], true))
        .expect_err("a separately sorted helper must not validate unsorted output keys");
    // The auxiliary witnesses themselves have true individual sum claims.
    // Rejection occurs when the verifier checks the prescribed permutation,
    // including when the optional honest-prover checks are enabled.
    assert!(matches!(
        err,
        SnarkError::VerifierError(VerifierError::VerifierCheckFailed(_))
    ));
}

#[test]
fn opposite_sort_direction_is_rejected() {
    for (output, asc) in [([4, 3, 2, 1], true), ([1, 2, 3, 4], false)] {
        let err = run_gadget_pipeline(harness(output, asc))
            .expect_err("output sorted in the opposite direction must be rejected");
        assert!(matches!(
            err,
            SnarkError::VerifierError(VerifierError::VerifierCheckFailed(_))
        ));
    }
}
